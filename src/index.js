// Constants
export {
    TAANQ_ADDRESS,
    ENS_INDELIBLE_ADDRESS,
    ENS_REGISTRY_ADDRESS,
    MERKLE_SPLIT,
    RESULT_CODE,
    RESULT_CODE_INFO,
    RESULT_CODE_PRIORITY,
    getPrimaryResultCode,
    getResultCodeCssClass,
} from './constants.js';

// Multi-chain client construction
export {
    CHAINS,
    DEFAULT_RPC_URLS,
    PUBLIC_RPC_URLS,
    CHAIN_DISPLAY_NAMES,
    DEFAULT_ALCHEMY_KEY,
    getChainKeyById,
    getChainById,
    createIndelibleClient,
} from './chains.js';

// Utilities (CID, hashing, Merkle, ENS DNS encoding, browser download)
export {
    merkleSplit,
    hashContent,
    hexHashContent,
    getCIDFromHash,
    getCIDFromRawDigest,
    prettifyTimestamp,
    createRawCIDv1,
    buildTree,
    dnsEncodeName,
    decodeCidToIpfsHash,
    attestationToRef,
    verificationResultToRef,
    downloadJson,
} from './utils.js';

// Verification
export {
    Attestation,
    VerificationResult,
    verifyRef,
    verifyCid,
    verifyQuoteProof,
    getAttestationByIndex,
    cidToAttestationIndices,
    cidAndAddressToAttestationIndices,
} from './verify.js';

// Publishing / writing actions
export {
    generateSalt,
    buildSaltedHash,
    commitAttestation,
    revealAttestation,
    revokeAttestation,
    delegate,
    revokeDelegation,
    proveQuote,
    registerEnsBinding,
    getExistingAttestationIndex,
    getDelegation,
} from './publish.js';
