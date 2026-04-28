// Constants
export {
    TAANQ_ADDRESS,
    ENS_INDELIBLE_ADDRESS,
    ENS_REGISTRY_ADDRESS,
    MERKLE_SPLIT,
    RESULT_CODE,
} from './constants.js';

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
    downloadJson,
} from './utils.js';

// Verification
export {
    Attestation,
    VerificationResult,
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
