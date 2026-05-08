# Polygon zkEVM RegTech Platform
## Privacy-Preserving KYC/AML Compliance with Zero-Knowledge Proofs

### Author : Uday Kumar BS

### Regulatory Scope
| Framework | Scope | Implementation |
|-----------|-------|----------------|
| **UK GDPR** | Data minimisation, erasure rights, privacy-by-design | Zero PII on-chain; Poseidon commitments only |
| **EU MiCA** | CASP KYC obligations, travel rule, EDD | zk-attested compliance; encrypted travel rule payloads |
| **eIDAS 2.0** | EUDIW wallet binding, qualified signatures | Identity commitment bound to EUDI Wallet DID |
| **ECA 2000** | Electronic signature validity | EIP-712 typed signatures anchored to identity commitments |

---

### Architecture Overview 

```
┌─────────────────────────────────────────────────────────────────────┐
│                     USER / CASP FRONTEND                            │
│   (Browser / EUDI Wallet / Mobile App)                              │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ HTTPS / REST API
┌──────────────────────────▼──────────────────────────────────────────┐
│                     BACKEND SERVICES                                 │
│  ┌─────────────┐ ┌──────────────┐ ┌─────────────┐ ┌─────────────┐ │
│  │ ProofService│ │ MiCA Service │ │ GDPR Manager│ │ AML Engine  │ │
│  │ (snarkjs)   │ │ (Travel Rule)│ │ (DSR/Breach)│ │ (Sanctions) │ │
│  └──────┬──────┘ └──────┬───────┘ └──────┬──────┘ └──────┬──────┘ │
│         │               │                │               │          │
│  ┌──────▼───────────────▼────────────────▼───────────────▼──────┐  │
│  │              Encrypted Identity Vault (AWS KMS)               │  │
│  │         PII stored here — NEVER sent on-chain                 │  │
│  └───────────────────────────────────────────────────────────────┘  │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ Groth16 Proof + Public Inputs
┌──────────────────────────▼──────────────────────────────────────────┐
│                  POLYGON zkEVM (chainId: 1101)                       │
│  ┌─────────────────────┐    ┌───────────────────────────────────┐   │
│  │  KYCProofVerifier   │◄───│         KYCRegistry               │   │
│  │  (Groth16 BN254)    │    │  - Attestations (commitments only) │   │
│  └─────────────────────┘    │  - AML Records (risk bands)       │   │
│                             │  - Travel Rule (encrypted blobs)  │   │
│                             │  - GDPR Erasure flags             │   │
│                             │  - eIDAS Wallet bindings          │   │
│                             └───────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

### Quick Start

#### Prerequisites
```bash
node >= 20.x
npm >= 10.x
circom >= 2.1.8
```

#### Install Dependencies
```bash
npm install
```

#### Configure Environment
```bash
cp .env.example .env
# Fill in:
#   DEPLOYER_PRIVATE_KEY=0x...
#   POLYGONSCAN_API_KEY=...
#   KYC_REGISTRY_ADDRESS=0x...
#   ICO_ENDPOINT=https://ico.org.uk/api/breach-report
#   CONSENT_PEPPER=<random-32-byte-hex>
```

#### Compile Contracts
```bash
npm run compile
```

#### Compile ZK Circuit
```bash
npm run circuit:compile
# Then run trusted setup (use real ceremony for production):
npm run circuit:setup
npm run circuit:contribute
npm run circuit:exportvk
```

#### Deploy to Testnet
```bash
npm run deploy:test
```

#### Deploy to Mainnet
```bash
# IMPORTANT: Complete these steps before mainnet deployment:
# 1. Conduct Powers of Tau ceremony with multiple parties
# 2. Audit contracts (Certora / Trail of Bits recommended)
# 3. Register as CASP with FCA under UK MLR 2017
# 4. Complete MiCA Art. 59 authorisation
# 5. Engage DPO and complete DPIA (GDPR Art. 35)
npm run deploy:main
```

---

### Project Structure
```
polygon-zkevm-regtech/
├── contracts/
│   ├── KYCRegistry.sol          # Main compliance registry (no PII on-chain)
│   └── KYCProofVerifier.sol     # Groth16 zk-SNARK verifier
├── circuits/
│   ├── kyc_proof.circom         # ZK circuit: KYC proof without PII disclosure
│   └── artifacts/               # Compiled circuit, zkey, verification key
├── backend/
│   └── src/
│       ├── proofService.ts      # zk-SNARK proof generation
│       ├── gdprCompliance.ts    # UK GDPR rights management
│       ├── micaCompliance.ts    # EU MiCA compliance + API routes
│       └── server.ts            # Express application entry point
├── scripts/
│   └── deploy.ts                # Deployment script
├── config/                      # Deployment records (auto-generated)
├── hardhat.config.ts
└── package.json
```

---

### Regulatory Compliance Notes

#### UK GDPR (Data Protection Act 2018)
- **Art. 5(1)(c) — Data minimisation**: Zero PII stored on-chain. Only Poseidon commitments.
- **Art. 17 — Right to erasure**: `requestErasure()` + `executeErasure()` on `KYCRegistry`.
- **Art. 25 — Privacy by design**: ZK proofs are the primary architectural mechanism.
- **Art. 33 — Breach notification**: 72-hour ICO notification enforced in `GDPRComplianceManager`.
- **Art. 35 — DPIA required** before deployment: Contact your DPO.

#### EU MiCA (Regulation 2023/1114)
- **Art. 59 — CASP authorisation**: `VERIFIER_ROLE` restricted to licensed CASPs only.
- **Art. 68 — KYC obligations**: Satisfied via on-chain zk-attested compliance status.
- **Art. 70 — Travel rule**: Encrypted originator/beneficiary data for >1000 EUR transfers.
- **Art. 83 — White paper**: `WhitepaperRecord` registry included.

#### eIDAS 2.0 (EU Regulation 2024/1183)
- **Art. 5a — EUDIW**: `bindEUDIWallet()` links identity commitment to EUDI Wallet DID.
- **Art. 8 — Assurance levels**: KYC attestation levels map to LoA Substantial/High.

#### Electronic Communications Act 2000
- **s.7(2) — Advanced electronic signature**: EIP-712 typed signing in `signAttestationRequest()`.
- Signature is uniquely linked to CASP, capable of identifying them, under sole control.

---

### Security Considerations
- Trusted setup ceremony MUST involve multiple independent parties
- Smart contracts should be audited before mainnet deployment
- Identity vault must use envelope encryption (AWS KMS / Azure Key Vault)
- Proof generation should occur in a trusted execution environment (TEE)
- Admin/governance should use a Gnosis Safe multisig (3-of-5 minimum)
