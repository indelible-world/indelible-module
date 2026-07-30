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

// ── Quote gap handling (ellipses / bracketed insertions) ────────────────────

/**
 * Matches a "gap" marker inside a quote: an ASCII ellipsis (three or more
 * dots), a Unicode ellipsis "…", or a bracketed editorial insertion/omission
 * such as "[sic]" or "[…]".
 */
export const QUOTE_GAP_PATTERN = /\.{3,}|…|\[[^\]]*\]/;

/**
 * Whether a quote contains any gap markers (ellipses or bracketed text).
 *
 * @param {string} quote
 * @returns {boolean}
 */
export function hasQuoteGaps(quote) {
    return QUOTE_GAP_PATTERN.test(quote);
}

/**
 * Split a quote on its gap markers (ellipses / bracketed insertions) into the
 * literal segments that must appear in the source text. Segments are trimmed
 * and empty segments are dropped.
 *
 * @param {string} quote
 * @returns {string[]}
 */
export function splitQuoteSegments(quote) {
    return quote
        .split(new RegExp(QUOTE_GAP_PATTERN.source, 'g'))
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
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

/**
 * Build a verify/quote reference object from an Attestation instance.
 *
 * @param {import('./verify.js').Attestation} attestation
 * @param {number} chainId
 * @returns {{ ipfsCid: string, chainId: number, authority: string, attestationIndex: number }}
 */
export function attestationToRef(attestation, chainId) {
    return {
        ipfsCid: attestation.cid,
        chainId,
        authority: attestation.authority,
        attestationIndex: Number(attestation.index),
    };
}

/**
 * Build a verify/quote reference object from the last attestation in a VerificationResult.
 *
 * @param {import('./verify.js').VerificationResult} verificationResult
 * @param {number} chainId
 * @returns {{ ipfsCid: string, chainId: number, authority: string, attestationIndex: number }}
 */
export function verificationResultToRef(verificationResult, chainId) {
    const attestation = verificationResult.attestations[verificationResult.attestations.length - 1];
    if (!attestation) {
        throw new Error('VerificationResult contains no attestations.');
    }
    return attestationToRef(attestation, chainId);
}

// ── DOM extraction helpers (browser-only) ────────────────────────────────────

/**
 * Collect visible text from `el`, recursively skipping any descendant
 * that carries `data-indelible-exclude`.
 *
 * @param {Element} el
 * @returns {string}
 */
export function collectExclusive(el) {
    let result = '';
    for (const node of el.childNodes) {
        if (node.nodeType === 3 /* TEXT_NODE */) {
            result += node.textContent;
        } else if (node.nodeType === 1 /* ELEMENT_NODE */) {
            if (node.hasAttribute('data-indelible-exclude')) continue;
            result += collectExclusive(node);
        }
    }
    return result;
}

/**
 * Collapse runs of whitespace into a single space and trim.
 *
 * @param {string} raw
 * @returns {string}
 */
export function normalise(raw) {
    return raw.replace(/\s+/g, ' ').trim();
}

/**
 * Scan the current document for Indelible markup and return all
 * extracted data, or null if this page carries no Indelible content.
 *
 * @param {Document} [doc] - DOM document to query. Defaults to the global `document` (browser).
 *   In Node.js, pass a `jsdom` document: `new JSDOM(html).window.document`.
 * @returns {{attestation: object|null, text: string, quotes: Array}|null}
 */
export function extractPageData(doc = document) {
    const root = doc.querySelector('[data-indelible]');
    if (!root) return null;

    // Parse the attestation metadata JSON (may be an empty object {}).
    let attestation = null;
    try {
        const raw = root.getAttribute('data-indelible').trim();
        if (raw) attestation = JSON.parse(raw);
    } catch (_) {
        // Leave attestation null — page is still Indelible-marked.
    }

    // Determine inclusion mode and extract attested text.
    const includes = Array.from(root.querySelectorAll('[data-indelible-include]'));

    let text;

    if (includes.length > 0) {
        // Inclusive mode: only explicitly marked elements contribute text.
        const seen = new Set();
        const parts = [];

        for (const el of includes) {
            // Skip elements whose ancestor is already collected (nested marks).
            let dominated = false;
            for (const ancestor of seen) {
                if (ancestor.contains(el)) { dominated = true; break; }
            }
            if (dominated) continue;
            seen.add(el);
            parts.push(el.textContent);
        }

        text = normalise(parts.join(' '));
    } else {
        // Exclusive mode: everything inside root is attested except excluded subtrees.
        text = normalise(collectExclusive(root));
    }

    // Collect embedded quote proofs (data-indelible-quote attributes).
    const quoteElements = Array.from(doc.querySelectorAll('[data-indelible-quote]'));
    const quotes = [];

    for (const el of quoteElements) {
        try {
            const proofData = JSON.parse(el.getAttribute('data-indelible-quote'));
            quotes.push({
                text: normalise(el.textContent),
                proofData,
            });
        } catch (_) {
            // Skip elements with malformed proof JSON.
        }
    }

    return { attestation, text, quotes };
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
