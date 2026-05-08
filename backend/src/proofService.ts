/**
 * ProofService — KYC zk-SNARK Proof Generation & Verification
 * ============================================================
 * Orchestrates off-chain proof generation and on-chain submission
 * for Polygon zkEVM KYC attestations.
 *
 * Regulatory scope:
 *   - UK GDPR Art. 25: PII processed only in encrypted vault, never transmitted raw
 *   - EU MiCA Art. 68: Proof satisfies CASP KYC obligation
 *   - eIDAS 2.0: Identity commitment anchored to EUDIW credential
 *   - ECA 2000 s.7: Electronic signature attached at proof submission
 */

import { buildPoseidon } from "circomlibjs";
import { groth16 } from "snarkjs";
import { ethers } from "ethers";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface KYCInput {
  /** Off-chain personal data — processed in encrypted enclave, never logged */
  dateOfBirth: number;       // YYYYMMDD integer — stays private
  documentHash: string;      // SHA-256 of KYC document — stays private
  sanctionsLeaf: bigint;     // Leaf in cleared-persons Merkle tree
  sanctionsPath: bigint[];   // Sibling hashes (20 levels)
  sanctionsIndices: number[]; // Left/right flags
  jurisdictionLeaf: bigint;  // Leaf in allowed-jurisdiction tree
  jurisdictionPath: bigint[];
  jurisdictionIndices: number[];
}

export interface ProofOutput {
  proof: {
    a:  [string, string];
    b:  [[string, string], [string, string]];
    c:  [string, string];
  };
  publicSignals: {
    identityCommitment: string;
    documentCommitment: string;
    ageAbove18:         string;
    notSanctioned:      string;
    jurisdictionRoot:   string;
    proofTimestamp:     string;
  };
  nullifier: string;
}

export interface AttestationRequest {
  nullifier:       string;
  identityCommit:  string;
  docCommit:       string;
  level:           number;      // ComplianceLevel enum
  jurisdiction:    number;      // JurisdictionFlag enum
  ttl:             number;      // seconds
  eidaSigned:      boolean;
  proof:           ProofOutput["proof"];
  pubInputs:       string[];
}

// ─── Constants ────────────────────────────────────────────────────────────────

const ARTIFACTS_DIR = path.resolve(__dirname, "../../circuits/artifacts");
const WASM_PATH     = path.join(ARTIFACTS_DIR, "kyc_proof.wasm");
const ZKEY_PATH     = path.join(ARTIFACTS_DIR, "kyc_proof_final.zkey");
const VKEY_PATH     = path.join(ARTIFACTS_DIR, "verification_key.json");

const SANCTIONS_LEVELS    = 20;
const JURISDICTION_LEVELS = 20;
const PROOF_REPLAY_WINDOW = 600; // 10 minutes

// ─── ProofService Class ───────────────────────────────────────────────────────

export class ProofService {
  private poseidon: any;
  private poseidonF: any;
  private vKey: any;

  constructor() {}

  async init() {
    this.poseidon  = await buildPoseidon();
    this.poseidonF = this.poseidon.F;
    this.vKey      = JSON.parse(fs.readFileSync(VKEY_PATH, "utf8"));
    console.log("[ProofService] Initialised — poseidon & vKey loaded");
  }

  // ─── Identity Commitment ───────────────────────────────────────────────────

  /**
   * Generate identity nullifier + secret pair.
   * MUST be stored in user's encrypted vault — never transmitted in plaintext.
   * UK GDPR Art. 32: Appropriate technical security measure.
   */
  generateIdentityKeys(): { nullifier: string; secret: string } {
    const nullifier = "0x" + crypto.randomBytes(31).toString("hex"); // 248 bits < BN254 order
    const secret    = "0x" + crypto.randomBytes(31).toString("hex");
    return { nullifier, secret };
  }

  /**
   * Compute Poseidon commitment from nullifier + secret.
   * This is the ONLY value stored on-chain.
   */
  async computeIdentityCommitment(nullifier: bigint, secret: bigint): Promise<bigint> {
    const hash = this.poseidon([nullifier, secret]);
    return this.poseidonF.toObject(hash);
  }

  /**
   * Compute document commitment from document hash + random salt.
   * documentHash: SHA-256 of KYC document bytes (e.g., passport scan)
   * Commitment stored on-chain; raw hash stays off-chain.
   */
  async computeDocumentCommitment(documentHash: bigint, docSalt: bigint): Promise<bigint> {
    const hash = this.poseidon([documentHash, docSalt]);
    return this.poseidonF.toObject(hash);
  }

  // ─── Proof Generation ─────────────────────────────────────────────────────

  /**
   * Generate a Groth16 zk-SNARK proof satisfying KYC circuit constraints.
   *
   * @param input    KYC data — processed in-memory only, never persisted
   * @param nullifier  Identity nullifier (from user's encrypted vault)
   * @param secret   Identity secret
   * @param jurisdictionRoot  Current jurisdiction Merkle root (from on-chain or trusted oracle)
   * @returns ProofOutput containing proof + public signals only
   */
  async generateKYCProof(
    input: KYCInput,
    nullifier: bigint,
    secret: bigint,
    jurisdictionRoot: bigint
  ): Promise<ProofOutput> {
    if (!this.poseidon) throw new Error("ProofService not initialised");

    const now = Math.floor(Date.now() / 1000);

    const identityCommitment = await this.computeIdentityCommitment(nullifier, secret);
    const docSalt = BigInt("0x" + crypto.randomBytes(31).toString("hex"));
    const docHashBigInt = BigInt("0x" + input.documentHash);
    const documentCommitment = await this.computeDocumentCommitment(docHashBigInt, docSalt);

    // Build circuit input — private fields stay in-memory
    const circuitInput = {
      // Public inputs
      identityCommitment: identityCommitment.toString(),
      documentCommitment: documentCommitment.toString(),
      ageAbove18:         "1",
      notSanctioned:      "1",
      jurisdictionRoot:   jurisdictionRoot.toString(),
      proofTimestamp:     now.toString(),

      // Private inputs (never leave this function scope in plaintext)
      nullifier:          nullifier.toString(),
      secret:             secret.toString(),
      dateOfBirth:        input.dateOfBirth.toString(),
      currentDate:        new Date().toISOString().slice(0, 10).replace(/-/g, ""),
      documentHash:       docHashBigInt.toString(),
      docSalt:            docSalt.toString(),

      // Merkle path arrays
      sanctionsLeaf:         input.sanctionsLeaf.toString(),
      sanctionsPathElements: input.sanctionsPath.map(x => x.toString()),
      sanctionsPathIndices:  input.sanctionsIndices.map(x => x.toString()),
      sanctionsRoot:         "0",  // Will be filled by circuit constraint
      jurisdictionLeaf:      input.jurisdictionLeaf.toString(),
      jurisdictionPathElements: input.jurisdictionPath.map(x => x.toString()),
      jurisdictionPathIndices:  input.jurisdictionIndices.map(x => x.toString()),
    };

    console.log("[ProofService] Generating Groth16 proof...");
    const startMs = Date.now();

    const { proof, publicSignals } = await groth16.fullProve(
      circuitInput,
      WASM_PATH,
      ZKEY_PATH
    );

    console.log(`[ProofService] Proof generated in ${Date.now() - startMs}ms`);

    // Verify locally before returning (belt-and-suspenders)
    const isValid = await groth16.verify(this.vKey, publicSignals, proof);
    if (!isValid) throw new Error("Local proof verification failed — circuit constraint violated");

    return {
      proof: {
        a: [proof.pi_a[0], proof.pi_a[1]],
        b: [[proof.pi_b[0][1], proof.pi_b[0][0]], [proof.pi_b[1][1], proof.pi_b[1][0]]],
        c: [proof.pi_c[0], proof.pi_c[1]],
      },
      publicSignals: {
        identityCommitment: publicSignals[0],
        documentCommitment: publicSignals[1],
        ageAbove18:         publicSignals[2],
        notSanctioned:      publicSignals[3],
        jurisdictionRoot:   publicSignals[4],
        proofTimestamp:     publicSignals[5],
      },
      nullifier: ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(["uint256", "uint256"], [nullifier, secret])
      ),
    };
  }

  // ─── Proof Verification ───────────────────────────────────────────────────

  /**
   * Verify a proof off-chain (pre-flight check before on-chain submission)
   */
  async verifyProofOffChain(
    proof: ProofOutput["proof"],
    publicSignals: string[]
  ): Promise<boolean> {
    const groth16Proof = {
      pi_a: [proof.a[0], proof.a[1], "1"],
      pi_b: [[proof.b[0][1], proof.b[0][0]], [proof.b[1][1], proof.b[1][0]], ["1", "0"]],
      pi_c: [proof.c[0], proof.c[1], "1"],
      protocol: "groth16",
      curve: "bn128",
    };

    return groth16.verify(this.vKey, publicSignals, groth16Proof);
  }

  // ─── Anti-Replay ──────────────────────────────────────────────────────────

  /**
   * Validate proof timestamp is within acceptable window
   */
  validateTimestamp(proofTimestamp: number): boolean {
    const now = Math.floor(Date.now() / 1000);
    return Math.abs(now - proofTimestamp) <= PROOF_REPLAY_WINDOW;
  }

  // ─── Document Hashing ─────────────────────────────────────────────────────

  /**
   * Compute SHA-256 hash of KYC document buffer.
   * Hash is used in the circuit; raw document is stored in encrypted vault only.
   * UK GDPR Art. 32 + eIDAS 2.0 Art. 5a compatibility.
   */
  hashDocument(documentBuffer: Buffer): string {
    return crypto.createHash("sha256").update(documentBuffer).digest("hex");
  }

  // ─── ECA 2000 Electronic Signature ───────────────────────────────────────

  /**
   * Attach an advanced electronic signature to the attestation request.
   * ECA 2000 s.7(2): Signature uniquely linked to signatory, capable of identifying them,
   * created using data under signatory's sole control.
   *
   * Uses EIP-712 typed data signing for Ethereum-compatible qualified signatures.
   */
  async signAttestationRequest(
    request: AttestationRequest,
    signerPrivateKey: string
  ): Promise<string> {
    const domain = {
      name:              "KYC RegTech Platform",
      version:           "1",
      chainId:           1101,   // Polygon zkEVM mainnet
      verifyingContract: process.env.KYC_REGISTRY_ADDRESS!,
    };

    const types = {
      AttestationRequest: [
        { name: "nullifier",      type: "bytes32" },
        { name: "identityCommit", type: "bytes32" },
        { name: "level",          type: "uint8"   },
        { name: "jurisdiction",   type: "uint8"   },
        { name: "ttl",            type: "uint256" },
        { name: "timestamp",      type: "uint256" },
      ],
    };

    const value = {
      nullifier:      request.nullifier,
      identityCommit: request.identityCommit,
      level:          request.level,
      jurisdiction:   request.jurisdiction,
      ttl:            request.ttl,
      timestamp:      Math.floor(Date.now() / 1000),
    };

    const wallet = new ethers.Wallet(signerPrivateKey);
    return wallet.signTypedData(domain, types, value);
  }
}

export default new ProofService();
