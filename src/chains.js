/**
 * Chain registry and viem client construction helpers for verifiers.
 *
 * The Indelible Protocol contracts are deployed at the same address on
 * every supported chain, so a verifier UI typically just needs to pick
 * which chain to connect to (often driven by a `chainId` embedded in a
 * proof file). These helpers encapsulate the boilerplate of mapping
 * chain keys / IDs to viem `Chain` objects and choosing an RPC transport.
 */

import { createPublicClient, http, fallback } from 'viem';
import { mainnet, arbitrum, base, sepolia } from 'viem/chains';

/**
 * Default Alchemy API key — restricted to the Indelible contract addresses
 * (see https://dashboard.alchemy.com/apps/lby6hxqj8ggxggxh/security ).
 * Override with a custom RPC URL via `createIndelibleClient`'s second arg.
 */
export const DEFAULT_ALCHEMY_KEY = '3Fxk_v1qhXH-B5SjNWXYo';

/**
 * Map of supported chain keys → viem `Chain` objects.
 */
export const CHAINS = {
    ethereum: mainnet,
    arbitrum,
    base,
    sepolia,
};

/**
 * Default (Alchemy) RPC URLs for each supported chain key.
 */
export const DEFAULT_RPC_URLS = {
    ethereum: `https://eth-mainnet.g.alchemy.com/v2/${DEFAULT_ALCHEMY_KEY}`,
    arbitrum: `https://arb-mainnet.g.alchemy.com/v2/${DEFAULT_ALCHEMY_KEY}`,
    base:     `https://base-mainnet.g.alchemy.com/v2/${DEFAULT_ALCHEMY_KEY}`,
    sepolia:  `https://eth-sepolia.g.alchemy.com/v2/${DEFAULT_ALCHEMY_KEY}`,
};

/**
 * Public, CORS-permissive fallback RPC URLs — used when the default
 * provider is blocked (e.g. when running inside an IPFS gateway).
 */
export const PUBLIC_RPC_URLS = {
    ethereum: 'https://cloudflare-eth.com',
    arbitrum: 'https://arb1.arbitrum.io/rpc',
    base:     'https://mainnet.base.org',
    sepolia:  'https://rpc.ankr.com/eth_sepolia',
};

/**
 * Human-readable display names keyed by numeric chain ID.
 */
export const CHAIN_DISPLAY_NAMES = {
    [mainnet.id]:  'Ethereum',
    [arbitrum.id]: 'Arbitrum',
    [base.id]:     'Base',
    [sepolia.id]:  'Sepolia',
};

/**
 * Look up the chain key (e.g. `'ethereum'`) for a numeric chain ID.
 *
 * @param {number} chainId
 * @returns {string|undefined} chain key, or undefined if unsupported
 */
export function getChainKeyById(chainId) {
    const entry = Object.entries(CHAINS).find(([, c]) => c.id === chainId);
    return entry?.[0];
}

/**
 * Look up the viem `Chain` object for a numeric chain ID.
 *
 * @param {number} chainId
 * @returns {import('viem').Chain|undefined}
 */
export function getChainById(chainId) {
    return Object.values(CHAINS).find(c => c.id === chainId);
}

/**
 * Build a viem `PublicClient` for an Indelible-supported chain.
 *
 * - If `customRpcUrl` is provided, it is used as the sole transport.
 * - Otherwise, a `fallback` transport is built from
 *   `DEFAULT_RPC_URLS[chainKey]` then `PUBLIC_RPC_URLS[chainKey]`.
 *
 * `chainOrKey` accepts either a chain key (e.g. `'ethereum'`), a numeric
 * chain ID, or a viem `Chain` object. Unknown chains fall back to Sepolia.
 *
 * @param {string|number|import('viem').Chain} chainOrKey
 * @param {string} [customRpcUrl]
 * @returns {import('viem').PublicClient}
 */
export function createIndelibleClient(chainOrKey, customRpcUrl) {
    let chainKey;

    if (typeof chainOrKey === 'string') {
        chainKey = chainOrKey;
    } else if (typeof chainOrKey === 'number') {
        chainKey = getChainKeyById(chainOrKey);
    } else if (chainOrKey && typeof chainOrKey === 'object' && 'id' in chainOrKey) {
        chainKey = getChainKeyById(chainOrKey.id);
    }

    const chain = CHAINS[chainKey] ?? sepolia;
    const trimmed = (customRpcUrl ?? '').trim();

    const transport = trimmed
        ? http(trimmed)
        : fallback([
            http(DEFAULT_RPC_URLS[chainKey] ?? DEFAULT_RPC_URLS.sepolia),
            http(PUBLIC_RPC_URLS[chainKey]  ?? PUBLIC_RPC_URLS.sepolia),
        ]);

    return createPublicClient({ chain, transport });
}
