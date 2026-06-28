// Constants
export {
    TAANQ_ADDRESS,
    ENS_INDELIBLE_ADDRESS,
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
    collectExclusive,
    normalise,
    extractPageData,
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

// ENS integration — read-side helpers grouped under the `ens` namespace.
// Usage: import { ens } from 'indelible'
//        const bindings = await ens.getBindingsByAddress(client, address)
import {
    EnsVerification,
    decodeDnsName,
    getVerification,
    getAddrToBindings,
    getNodeToBinding,
    resolveIndelibleAddress,
    getBindingsByAddress,
    getBindingByName,
    getBindingByNode,
} from './ens.js';

export const ens = {
    EnsVerification,
    decodeDnsName,
    getVerification,
    getAddrToBindings,
    getNodeToBinding,
    resolveIndelibleAddress,
    getBindingsByAddress,
    getBindingByName,
    getBindingByNode,
};

// Publishing / writing actions
export {
    generateSalt,
    buildSaltedHash,
    commitAttestation,
    revealAttestation,
    revokeAttestation,
    setChildIpfsHash,
    delegate,
    revokeDelegation,
    proveQuote,
    registerEnsBinding,
    getExistingAttestationIndex,
    getDelegation,
} from './publish.js';
