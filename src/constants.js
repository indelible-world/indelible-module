// Indelible Protocol contract addresses (deployed on multiple chains at the same address).
export const TAANQ_ADDRESS = '0x000000d505a5eaa8c108537Ce40Aa61E4A27D381';
export const ENS_INDELIBLE_ADDRESS = '0x0000006c07ba8745BEA0becAAF5f5fc143eC5b52';

// Canonical ENS Registry (mainnet & supported testnets).
export const ENS_REGISTRY_ADDRESS = '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e';

// Merkle chunking size used when building per-character/quote proofs.
// See https://www.desmos.com/calculator/htfwridftb for calculations that led to the number 46 being chosen as the optimal chunk size
export const MERKLE_SPLIT = 46;

// Result codes returned by verifyCid().
export const RESULT_CODE = {
    NOT_FOUND: 0,
    VERIFIED: 1,
    UNVERIFIED: 2,
    REVOKED: 3,
    WARNING: 4,
};

/**
 * Metadata for each result code: human label, CSS class hint, and
 * priority (lower number = higher priority when multiple codes are present).
 *
 * Priority order encodes: a single UNVERIFIED or REVOKED in a result set
 * should dominate over VERIFIED, since they represent active failures.
 * NOT_FOUND and WARNING fall in between.
 */
export const RESULT_CODE_INFO = {
    [RESULT_CODE.NOT_FOUND]:  { label: 'Not Found',  cssClass: 'result-not-found',  priority: 2 },
    [RESULT_CODE.VERIFIED]:   { label: 'Verified',   cssClass: 'result-verified',   priority: 4 },
    [RESULT_CODE.UNVERIFIED]: { label: 'Unverified', cssClass: 'result-unverified', priority: 0 },
    [RESULT_CODE.REVOKED]:    { label: 'Revoked',    cssClass: 'result-revoked',    priority: 1 },
    [RESULT_CODE.WARNING]:    { label: 'Warning',    cssClass: 'result-warning',    priority: 3 },
};

/**
 * Order in which to pick a "primary" code from a multi-code result.
 * Derived from RESULT_CODE_INFO priorities.
 */
export const RESULT_CODE_PRIORITY = Object.entries(RESULT_CODE_INFO)
    .sort(([, a], [, b]) => a.priority - b.priority)
    .map(([code]) => Number(code));

/**
 * Pick the primary (highest-priority) result code from an array of codes.
 *
 * @param {number[]} codes
 * @returns {number}
 */
export function getPrimaryResultCode(codes) {
    if (!codes || codes.length === 0) return undefined;
    return RESULT_CODE_PRIORITY.find(c => codes.includes(c)) ?? codes[codes.length - 1];
}

/**
 * Get the CSS class associated with a result code (e.g. `'result-verified'`).
 *
 * @param {number} code
 * @returns {string|undefined}
 */
export function getResultCodeCssClass(code) {
    return RESULT_CODE_INFO[code]?.cssClass;
}
