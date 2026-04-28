import { StandardMerkleTree } from '@openzeppelin/merkle-tree';
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';
import * as Digest from 'multiformats/hashes/digest';
import * as raw from 'multiformats/codecs/raw';
import { base32 } from 'multiformats/bases/base32';
import { toHex } from 'viem';

import { MERKLE_SPLIT } from './constants.js';

export const merkleSplit = MERKLE_SPLIT;

export async function hashContent(data) {
    if (typeof data === 'string') {
        data = new TextEncoder().encode(data);
    }
    const multihash = await sha256.digest(data);
    return new Uint8Array(multihash.digest);
}

export async function hexHashContent(data) {
    return toHex(await hashContent(data));
}

export async function getCIDFromHash(hash) {
    const cid = CID.createV1(raw.code, hash);
    return cid.toString(base32);
}

// Reconstruct a CID from a raw 32-byte SHA-256 digest (as stored on-chain).
export function getCIDFromRawDigest(digestBytes) {
    const multihash = Digest.create(sha256.code, digestBytes);
    const cid = CID.createV1(raw.code, multihash);
    return cid.toString(base32);
}

export function prettifyTimestamp(timestamp) {
    return new Date(Number(timestamp) * 1000).toLocaleString();
}

export async function createRawCIDv1(data) {
    if (typeof data === 'string') {
        data = new TextEncoder().encode(data);
    }
    const multihash = await sha256.digest(data);
    return getCIDFromHash(multihash);
}

export function buildTree(text) {
    const chunks = [];
    for (let i = 0; i < text.length; i += MERKLE_SPLIT) {
        chunks.push(text.slice(i, i + MERKLE_SPLIT));
    }

    const values = chunks.map((chunk, i) => [i.toString(), chunk]);

    return StandardMerkleTree.of(values, ['string', 'string']);
}

export function dnsEncodeName(name) {
    const labels = name.replace(/\.$/, '').split('.');
    const parts = [];
    for (const label of labels) {
        const encoded = new TextEncoder().encode(label);
        if (encoded.length === 0 || encoded.length > 63) {
            throw new Error(`Invalid label: "${label}"`);
        }
        parts.push(encoded.length);
        parts.push(...encoded);
    }
    parts.push(0);
    return toHex(new Uint8Array(parts));
}

// Decode a base32lower CIDv1 to extract the raw SHA-256 digest as bytes32 hex.
export function decodeCidToIpfsHash(cidStr) {
    const parsed = CID.parse(cidStr, base32);
    return toHex(new Uint8Array(parsed.multihash.digest));
}

// Browser-only: trigger download of an object as a JSON file.
export function downloadJson(data, filename) {
    if (typeof document === 'undefined') {
        throw new Error('downloadJson is only available in browser environments.');
    }
    const blob = new Blob([JSON.stringify(data, null, 4)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}
