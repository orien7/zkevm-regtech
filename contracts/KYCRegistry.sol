// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title KYCRegistry
 * @notice Privacy-preserving KYC/AML compliance registry on Polygon zkEVM
 * @dev Regulatory scope: UK GDPR, EU MiCA, eIDAS 2.0, Electronic Communications Act 2000
 *
 * Design Principles:
 *  - Zero-knowledge proofs: PII never stored on-chain (UK GDPR Art. 5, 25)
 *  - Attestation model: compliance status proven without data disclosure
 *  - MiCA Art. 68-69: CASP KYC obligations satisfied via zk-attestations
 *  - eIDAS 2.0 Art. 5a: EUDIW-compatible identity assertions
 *  - ECA 2000 s.7: electronic signatures anchored to verified identity commitments
 */

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

interface IZKVerifier {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata publicInputs
    ) external view returns (bool);
}

contract KYCRegistry is AccessControl, ReentrancyGuard, Pausable {

    // ─── Roles ────────────────────────────────────────────────────────────────
    bytes32 public constant REGULATOR_ROLE    = keccak256("REGULATOR_ROLE");
    bytes32 public constant VERIFIER_ROLE     = keccak256("VERIFIER_ROLE");   // Licensed VASPs / CASPs
    bytes32 public constant AUDITOR_ROLE      = keccak256("AUDITOR_ROLE");    // FCA / competent authority
    bytes32 public constant PAUSER_ROLE       = keccak256("PAUSER_ROLE");

    // ─── Enums ────────────────────────────────────────────────────────────────
    enum ComplianceLevel { NONE, BASIC, ENHANCED, INSTITUTIONAL }
    enum JurisdictionFlag { NONE, UK, EU, GLOBAL }
    enum DataRetentionPolicy { STANDARD_5Y, EXTENDED_10Y, GDPR_ERASURE_REQUESTED }

    // ─── Structs ──────────────────────────────────────────────────────────────

    /**
     * @dev On-chain attestation — contains NO PII per GDPR Art. 5(1)(c) data minimisation.
     *      All personal data lives off-chain in an encrypted vault; only commitments stored here.
     */
    struct KYCAttestation {
        bytes32  identityCommitment;    // Poseidon hash of identity nullifier + secret
        bytes32  documentCommitment;    // Commitment to doc hash (no raw doc data)
        address  verifierAddress;       // Licensed CASP/VASP that performed KYC
        uint48   issuedAt;             // Unix timestamp
        uint48   expiresAt;            // TTL per MiCA Art. 68(2)
        uint48   lastUpdated;
        ComplianceLevel  level;
        JurisdictionFlag jurisdiction;
        DataRetentionPolicy retentionPolicy;
        bool     eidaSigned;            // eIDAS 2.0 qualified signature present
        bool     active;
        bytes32  auditTrailRoot;        // Merkle root of audit events (off-chain)
    }

    /**
     * @dev AML risk score — computed off-chain by TM engine, committed on-chain
     */
    struct AMLAttestation {
        bytes32  riskCommitment;        // Commitment to risk score without revealing it
        uint8    riskBand;              // 1=Low, 2=Medium, 3=High (band not raw score)
        uint48   assessedAt;
        address  assessingVASP;
        bool     sanctionsScreened;
        bool     pepScreened;
        bytes32  screeningBatchRoot;    // Merkle root of screening batch for auditability
    }

    /**
     * @dev MiCA-specific travel rule data (FATF R.16)
     *      Originator/beneficiary info hashed — disclosed only to regulators
     */
    struct TravelRuleRecord {
        bytes32  originatorCommitment;
        bytes32  beneficiaryCommitment;
        uint256  transactionAmount;
        bytes32  assetIdentifier;       // MiCA asset classification
        uint48   timestamp;
        bool     thresholdBreached;     // >1000 EUR per MiCA Art. 70
        bytes    regulatorEncryptedData; // AES-256-GCM blob, only FCA/regulator key decrypts
    }

    // ─── State ────────────────────────────────────────────────────────────────
    IZKVerifier public immutable zkVerifier;

    // nullifier => attestation (prevents double-registration)
    mapping(bytes32 => KYCAttestation)   public attestations;
    mapping(bytes32 => AMLAttestation)   public amlRecords;
    mapping(bytes32 => TravelRuleRecord[]) public travelRules;
    mapping(bytes32 => bool)             public revokedNullifiers;
    mapping(address => bool)             public authorisedVerifiers;  // MiCA licensed CASPs

    // GDPR Art. 17 erasure requests
    mapping(bytes32 => bool)             public erasureRequested;
    mapping(bytes32 => uint48)           public erasureRequestedAt;

    // eIDAS 2.0 — wallet binding
    mapping(bytes32 => bytes32)          public eudiWalletBinding;  // commitment => wallet DID hash

    uint256 public totalAttestations;
    uint256 public constant TRAVEL_RULE_THRESHOLD_EUR = 1000;
    uint256 public constant KYC_DEFAULT_TTL = 365 days;
    uint256 public constant AML_REFRESH_INTERVAL = 90 days;

    // ─── Events ───────────────────────────────────────────────────────────────
    event AttestationIssued(
        bytes32 indexed nullifier,
        address indexed verifier,
        ComplianceLevel level,
        JurisdictionFlag jurisdiction,
        uint48 expiresAt
    );
    event AttestationRevoked(bytes32 indexed nullifier, address indexed revokedBy, string reason);
    event AMLRecordUpdated(bytes32 indexed nullifier, uint8 riskBand, address indexed assessor);
    event TravelRuleRecorded(bytes32 indexed nullifier, bool thresholdBreached);
    event ErasureRequested(bytes32 indexed nullifier, uint48 requestedAt);
    event ErasureExecuted(bytes32 indexed nullifier);
    event EUDIWalletBound(bytes32 indexed nullifier, bytes32 walletHash);
    event VerifierAuthorised(address indexed verifier, bool status);
    event RegulatorDataAccess(bytes32 indexed nullifier, address indexed regulator, uint48 accessedAt);

    // ─── Errors ───────────────────────────────────────────────────────────────
    error InvalidProof();
    error AttestationExpired();
    error AttestationAlreadyExists();
    error NullifierRevoked();
    error UnauthorisedVerifier();
    error ErasureAlreadyRequested();
    error InvalidTTL();
    error ZeroCommitment();

    // ─── Constructor ──────────────────────────────────────────────────────────
    constructor(address _zkVerifier, address _admin) {
        require(_zkVerifier != address(0) && _admin != address(0), "Zero addr");
        zkVerifier = IZKVerifier(_zkVerifier);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(PAUSER_ROLE, _admin);
        _grantRole(REGULATOR_ROLE, _admin);
    }

    // ─── Core Functions ───────────────────────────────────────────────────────

    /**
     * @notice Issue a KYC attestation after zk-proof verification
     * @dev MiCA Art. 68 + eIDAS 2.0 Art. 5a compliance entry point
     * @param nullifier      Identity nullifier (Poseidon(trapdoor, secret))
     * @param identityCommit Commitment to identity data
     * @param docCommit      Commitment to KYC document
     * @param level          Compliance tier
     * @param jurisdiction   Regulatory jurisdiction
     * @param ttl            Time-to-live in seconds
     * @param eidaSigned     Whether eIDAS 2.0 QES is present
     * @param a,b,c,pubInputs  Groth16 zk-SNARK proof components
     */
    function issueAttestation(
        bytes32 nullifier,
        bytes32 identityCommit,
        bytes32 docCommit,
        ComplianceLevel level,
        JurisdictionFlag jurisdiction,
        uint256 ttl,
        bool eidaSigned,
        uint256[2]    calldata a,
        uint256[2][2] calldata b,
        uint256[2]    calldata c,
        uint256[]     calldata pubInputs
    ) external nonReentrant whenNotPaused onlyRole(VERIFIER_ROLE) {
        if (!authorisedVerifiers[msg.sender])  revert UnauthorisedVerifier();
        if (revokedNullifiers[nullifier])       revert NullifierRevoked();
        if (attestations[nullifier].active)     revert AttestationAlreadyExists();
        if (identityCommit == bytes32(0))       revert ZeroCommitment();
        if (ttl == 0 || ttl > 5 * 365 days)    revert InvalidTTL();

        // Verify zk-SNARK — proves KYC checks passed without revealing identity
        if (!zkVerifier.verifyProof(a, b, c, pubInputs)) revert InvalidProof();

        uint48 now48   = uint48(block.timestamp);
        uint48 expiry  = uint48(block.timestamp + ttl);

        attestations[nullifier] = KYCAttestation({
            identityCommitment: identityCommit,
            documentCommitment: docCommit,
            verifierAddress:    msg.sender,
            issuedAt:           now48,
            expiresAt:          expiry,
            lastUpdated:        now48,
            level:              level,
            jurisdiction:       jurisdiction,
            retentionPolicy:    DataRetentionPolicy.STANDARD_5Y,
            eidaSigned:         eidaSigned,
            active:             true,
            auditTrailRoot:     bytes32(0)
        });

        totalAttestations++;
        emit AttestationIssued(nullifier, msg.sender, level, jurisdiction, expiry);
    }

    /**
     * @notice Verify compliance status — returns bool, no PII disclosed (GDPR data minimisation)
     * @param nullifier       Identity nullifier
     * @param requiredLevel   Minimum compliance level required
     */
    function verifyCompliance(
        bytes32 nullifier,
        ComplianceLevel requiredLevel
    ) external view returns (bool valid, uint48 expiresAt) {
        if (revokedNullifiers[nullifier]) return (false, 0);
        KYCAttestation storage att = attestations[nullifier];
        if (!att.active) return (false, 0);
        if (block.timestamp > att.expiresAt) return (false, att.expiresAt);
        if (uint8(att.level) < uint8(requiredLevel)) return (false, att.expiresAt);
        return (true, att.expiresAt);
    }

    /**
     * @notice Record AML risk assessment (off-chain engine result committed on-chain)
     */
    function recordAMLAssessment(
        bytes32 nullifier,
        bytes32 riskCommitment,
        uint8   riskBand,
        bool    sanctionsScreened,
        bool    pepScreened,
        bytes32 screeningBatchRoot
    ) external onlyRole(VERIFIER_ROLE) {
        require(attestations[nullifier].active, "No active attestation");
        require(riskBand >= 1 && riskBand <= 3, "Invalid risk band");

        amlRecords[nullifier] = AMLAttestation({
            riskCommitment:   riskCommitment,
            riskBand:         riskBand,
            assessedAt:       uint48(block.timestamp),
            assessingVASP:    msg.sender,
            sanctionsScreened: sanctionsScreened,
            pepScreened:      pepScreened,
            screeningBatchRoot: screeningBatchRoot
        });

        emit AMLRecordUpdated(nullifier, riskBand, msg.sender);
    }

    /**
     * @notice Record travel rule data for threshold-breaching transactions (MiCA Art. 70)
     */
    function recordTravelRule(
        bytes32 nullifier,
        bytes32 originatorCommit,
        bytes32 beneficiaryCommit,
        uint256 amount,
        bytes32 assetId,
        bool    thresholdBreached,
        bytes calldata regulatorEncrypted
    ) external onlyRole(VERIFIER_ROLE) {
        require(attestations[nullifier].active, "No active attestation");

        travelRules[nullifier].push(TravelRuleRecord({
            originatorCommitment:   originatorCommit,
            beneficiaryCommitment:  beneficiaryCommit,
            transactionAmount:      amount,
            assetIdentifier:        assetId,
            timestamp:              uint48(block.timestamp),
            thresholdBreached:      thresholdBreached,
            regulatorEncryptedData: regulatorEncrypted
        }));

        emit TravelRuleRecorded(nullifier, thresholdBreached);
    }

    /**
     * @notice Bind eIDAS 2.0 EUDI Wallet DID to identity commitment
     */
    function bindEUDIWallet(
        bytes32 nullifier,
        bytes32 walletDIDHash
    ) external onlyRole(VERIFIER_ROLE) {
        require(attestations[nullifier].active, "No active KYC");
        eudiWalletBinding[nullifier] = walletDIDHash;
        emit EUDIWalletBound(nullifier, walletDIDHash);
    }

    /**
     * @notice GDPR Art. 17 — right to erasure request
     *         Off-chain data must be deleted; on-chain commitment is pseudonymous
     */
    function requestErasure(bytes32 nullifier) external {
        require(attestations[nullifier].active, "Not found");
        if (erasureRequested[nullifier]) revert ErasureAlreadyRequested();

        erasureRequested[nullifier] = true;
        erasureRequestedAt[nullifier] = uint48(block.timestamp);
        attestations[nullifier].retentionPolicy = DataRetentionPolicy.GDPR_ERASURE_REQUESTED;

        emit ErasureRequested(nullifier, uint48(block.timestamp));
    }

    /**
     * @notice Execute erasure — zeros on-chain commitments, revokes attestation
     *         Called by admin after off-chain vault deletion confirmed
     */
    function executeErasure(bytes32 nullifier) external onlyRole(REGULATOR_ROLE) {
        require(erasureRequested[nullifier], "No erasure request");

        KYCAttestation storage att = attestations[nullifier];
        att.identityCommitment = bytes32(0);
        att.documentCommitment = bytes32(0);
        att.active             = false;
        revokedNullifiers[nullifier] = true;

        emit ErasureExecuted(nullifier);
    }

    /**
     * @notice Revoke attestation (sanctions hit, fraud detected, regulatory order)
     */
    function revokeAttestation(
        bytes32 nullifier,
        string calldata reason
    ) external onlyRole(REGULATOR_ROLE) {
        attestations[nullifier].active = false;
        revokedNullifiers[nullifier]   = true;
        emit AttestationRevoked(nullifier, msg.sender, reason);
    }

    /**
     * @notice Regulator data access log — FCA/competent authority audit trail
     */
    function logRegulatorAccess(bytes32 nullifier) external onlyRole(AUDITOR_ROLE) {
        require(attestations[nullifier].active || revokedNullifiers[nullifier], "Not found");
        emit RegulatorDataAccess(nullifier, msg.sender, uint48(block.timestamp));
    }

    // ─── Admin ────────────────────────────────────────────────────────────────
    function setVerifierAuthorisation(address verifier, bool authorised) external onlyRole(REGULATOR_ROLE) {
        authorisedVerifiers[verifier] = authorised;
        emit VerifierAuthorised(verifier, authorised);
    }

    function updateAuditTrailRoot(bytes32 nullifier, bytes32 root) external onlyRole(AUDITOR_ROLE) {
        attestations[nullifier].auditTrailRoot = root;
    }

    function pause()   external onlyRole(PAUSER_ROLE) { _pause(); }
    function unpause() external onlyRole(PAUSER_ROLE) { _unpause(); }
}
