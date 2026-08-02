/**
 * Read-side ENS integration for the Indelible Protocol.
 *
 * The ENS Indelible contract (`ENS_INDELIBLE_ADDRESS`) maps Ethereum
 * addresses to ENS names (and vice-versa) via on-chain verification records.
 * These helpers provide typed access to those records.
 */

import { namehash } from 'viem';
import { normalize } from 'viem/ens';

import ensAbi from './abi/ensAbi.json' with { type: 'json' };
import { ENS_INDELIBLE_ADDRESS } from './constants.js';

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/**
 * A single ENS-to-address verification record stored on chain.
 */
export class EnsVerification {
    /**
     * @param {`0x${string}`} authority  Ethereum address that owns this binding.
     * @param {`0x${string}`} node       ENS namehash of the bound name.
     * @param {Uint8Array|`0x${string}`} dnsName  DNS-wire-format encoded name.
     * @param {number} startTimestamp  Unix timestamp (seconds) when the binding became active.
     * @param {number} endTimestamp    Unix timestamp (seconds) when revoked, or 0 if still active.
     * @param {number} index           Position in the on-chain `verifications` array.
     */
    constructor(authority, node, dnsName, startTimestamp, endTimestamp, index) {
        this.authority = authority;
        this.node = node;
        this.dnsName = dnsName;
        this.startTimestamp = startTimestamp;
        this.endTimestamp = endTimestamp;
        this.index = index;
    }

    /** Whether the binding is currently active. */
    get isActive() {
        const now = Math.floor(Date.now() / 1000);
        return this.isActiveAt(now);
    }

    /** Whether the binding was active at the given Unix timestamp (seconds). */
    isActiveAt(timestamp) {
        return this.startTimestamp <= timestamp &&
            (this.endTimestamp === 0 || this.endTimestamp > timestamp);
    }

    /** Human-readable ENS name decoded from the stored DNS-wire bytes. */
    get name() {
        return decodeDnsName(this.dnsName);
    }
}

// ---------------------------------------------------------------------------
// Pure utilities
// ---------------------------------------------------------------------------

/**
 * Decode a DNS-wire-format encoded name (as stored on-chain) to a
 * dot-separated string (e.g. `"vitalik.eth"`).
 *
 * Accepts either a hex string (`0x…`) or a `Uint8Array`.
 *
 * @param {`0x${string}`|Uint8Array} hexOrBytes
 * @returns {string}
 */
export function decodeDnsName(hexOrBytes) {
    let bytes;
    if (typeof hexOrBytes === 'string' && hexOrBytes.startsWith('0x')) {
        bytes = new Uint8Array(hexOrBytes.slice(2).match(/.{2}/g).map(b => parseInt(b, 16)));
    } else if (hexOrBytes instanceof Uint8Array) {
        bytes = hexOrBytes;
    } else {
        return '(unknown)';
    }
    const labels = [];
    let i = 0;
    while (i < bytes.length) {
        const len = bytes[i];
        if (len === 0) break;
        i++;
        const label = new TextDecoder().decode(bytes.slice(i, i + len));
        labels.push(label);
        i += len;
    }
    return labels.join('.') || '(unknown)';
}

// ---------------------------------------------------------------------------
// Low-level contract reads
// ---------------------------------------------------------------------------

/**
 * Read a single verification record by its index in the on-chain array.
 *
 * @param {import('viem').PublicClient} client
 * @param {number|bigint} index
 * @param {{ ensIndelibleAddress?: `0x${string}` }} [opts]
 * @returns {Promise<EnsVerification|null>}
 */
export async function getVerification(client, index, opts = {}) {
    try {
        const result = await client.readContract({
            address: opts.ensIndelibleAddress ?? ENS_INDELIBLE_ADDRESS,
            abi: ensAbi,
            functionName: 'verifications',
            args: [index],
        });
        return new EnsVerification(
            result[0],
            result[1],
            result[2],
            Number(result[3]),
            Number(result[4]),
            Number(index),
        );
    } catch {
        return null;
    }
}

/**
 * Read the verification index stored in `addrToBindings[address][i]`.
 *
 * Returns `0` (sentinel for "no binding") when the slot is empty or the call
 * reverts.
 *
 * @param {import('viem').PublicClient} client
 * @param {`0x${string}`} address
 * @param {number|bigint} i  Slot index in the address's binding list.
 * @param {{ ensIndelibleAddress?: `0x${string}` }} [opts]
 * @returns {Promise<number>}
 */
export async function getAddrToBindings(client, address, i, opts = {}) {
    try {
        const result = await client.readContract({
            address: opts.ensIndelibleAddress ?? ENS_INDELIBLE_ADDRESS,
            abi: ensAbi,
            functionName: 'addrToBindings',
            args: [address, i],
        });
        return Number(result);
    } catch {
        return 0;
    }
}

/**
 * Read the verification index stored in `nodeToBinding[node]`.
 *
 * Returns `0` when no binding exists for the node.
 *
 * @param {import('viem').PublicClient} client
 * @param {`0x${string}`} node  ENS namehash.
 * @param {{ ensIndelibleAddress?: `0x${string}` }} [opts]
 * @returns {Promise<number>}
 */
export async function getNodeToBinding(client, node, opts = {}) {
    try {
        const result = await client.readContract({
            address: opts.ensIndelibleAddress ?? ENS_INDELIBLE_ADDRESS,
            abi: ensAbi,
            functionName: 'nodeToBinding',
            args: [node],
        });
        return Number(result);
    } catch {
        return 0;
    }
}

/**
 * Resolve the Ethereum address that an ENS name's `indelible-address` text
 * record points to, as returned by the ENS Indelible contract.
 *
 * With ENSv2 / the Universal Resolver, the contract resolves the record from
 * the DNS-wire-format name, so both the encoded `dnsName` and the `node`
 * namehash must be supplied.
 *
 * Returns `null` if unresolvable or the zero address.
 *
 * @param {import('viem').PublicClient} client
 * @param {`0x${string}`|Uint8Array} dnsName  DNS-wire-format encoded name.
 * @param {`0x${string}`} node  ENS namehash.
 * @param {{ ensIndelibleAddress?: `0x${string}` }} [opts]
 * @returns {Promise<`0x${string}`|null>}
 */
export async function resolveIndelibleAddress(client, dnsName, node, opts = {}) {
    try {
        const result = await client.readContract({
            address: opts.ensIndelibleAddress ?? ENS_INDELIBLE_ADDRESS,
            abi: ensAbi,
            functionName: 'resolveIndelibleAddress',
            args: [dnsName, node],
        });
        if (!result || result === '0x0000000000000000000000000000000000000000') return null;
        return result;
    } catch {
        return null;
    }
}

// ---------------------------------------------------------------------------
// High-level helpers
// ---------------------------------------------------------------------------

/**
 * Fetch all verification records bound to an Ethereum address.
 *
 * Iterates `addrToBindings` until a zero sentinel is returned, then fetches
 * each corresponding `verifications` record.
 *
 * If `opts.timestamp` is provided (Unix seconds), only bindings that were
 * active at that point in time are returned. Omit it to get all bindings
 * regardless of status.
 *
 * @param {import('viem').PublicClient} client
 * @param {`0x${string}`} address
 * @param {{ ensIndelibleAddress?: `0x${string}`, timestamp?: number }} [opts]
 * @returns {Promise<EnsVerification[]>}
 */
export async function getBindingsByAddress(client, address, opts = {}) {
    const bindings = [];
    let i = 0;
    while (true) {
        const bindingIndex = await getAddrToBindings(client, address, i, opts);
        if (bindingIndex === 0) break;
        const verification = await getVerification(client, bindingIndex, opts);
        if (verification) bindings.push(verification);
        i++;
    }
    if (opts.timestamp !== undefined) {
        return bindings.filter(b => b.isActiveAt(opts.timestamp));
    }
    return bindings;
}

/**
 * Fetch the verification record for a given ENS name.
 *
 * The name is normalised via `viem/ens` `normalize` before hashing.
 * Returns `null` if no binding exists.
 *
 * @param {import('viem').PublicClient} client
 * @param {string} ensName  Human-readable ENS name (e.g. `"vitalik.eth"`).
 * @param {{ ensIndelibleAddress?: `0x${string}` }} [opts]
 * @returns {Promise<EnsVerification|null>}
 */
export async function getBindingByName(client, ensName, opts = {}) {
    let normalizedName;
    try {
        normalizedName = normalize(ensName);
    } catch {
        normalizedName = ensName.trim().toLowerCase();
    }
    const node = namehash(normalizedName);
    const bindingIndex = await getNodeToBinding(client, node, opts);
    if (bindingIndex === 0) return null;
    return getVerification(client, bindingIndex, opts);
}

/**
 * Fetch the verification record for a pre-computed ENS namehash node.
 *
 * Returns `null` if no binding exists.
 *
 * @param {import('viem').PublicClient} client
 * @param {`0x${string}`} node  ENS namehash.
 * @param {{ ensIndelibleAddress?: `0x${string}` }} [opts]
 * @returns {Promise<EnsVerification|null>}
 */
export async function getBindingByNode(client, node, opts = {}) {
    const bindingIndex = await getNodeToBinding(client, node, opts);
    if (bindingIndex === 0) return null;
    return getVerification(client, bindingIndex, opts);
}