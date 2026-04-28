// Indelible Protocol contract addresses (deployed on multiple chains at the same address).
export const TAANQ_ADDRESS = '0x111111a2eb2791b3ee98c5a55972576c54b05b46';
export const ENS_INDELIBLE_ADDRESS = '0x1111113661d1fbd85b6d131beb199063582c2be7';

// Canonical ENS Registry (mainnet & supported testnets).
export const ENS_REGISTRY_ADDRESS = '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e';

// Merkle chunking size used when building per-character/quote proofs.
export const MERKLE_SPLIT = 46;

// Result codes returned by verifyCid().
export const RESULT_CODE = {
    NOT_FOUND: 0,
    VERIFIED: 1,
    UNVERIFIED: 2,
    REVOKED: 3,
    WARNING: 4,
};
