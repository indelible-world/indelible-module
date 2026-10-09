import { RESULT_CODE } from './constants.js';
import { commitAttestation, buildAttestationRef, proveQuote } from './publish.js';
import { createRawCIDv1, hexHashContent, normalise } from './utils.js';
import { VerificationResult, verifyCid, verifyQuoteProof, verifyRef } from './verify.js';

// The attested artifact is the canonical extracted TEXT, never the PDF bytes, so embedding
// metadata (which rewrites the file) does not change the CID.

export const INDELIBLE_ATTACHMENT = 'indelible.json';
const QUOTE_ATTACHMENT_PREFIX = 'indelible-quote-';
const QUOTE_ATTACHMENT_PATTERN = /^indelible-quote-.+\.json$/;

const LIGATURES = { 'ﬀ': 'ff', 'ﬁ': 'fi', 'ﬂ': 'fl', 'ﬃ': 'ffi', 'ﬄ': 'ffl', 'ﬅ': 'st', 'ﬆ': 'st' };

async function loadOptional(importer, pkg) {
    try {
        return await importer();
    } catch (cause) {
        throw new Error(`"${pkg}" is required for PDF support. Install it with: npm install ${pkg}`, { cause });
    }
}

const loadPdfjs = () => loadOptional(() => import('pdfjs-dist/legacy/build/pdf.mjs'), 'pdfjs-dist');
const loadPdfLib = () => loadOptional(() => import('pdf-lib'), 'pdf-lib');

// pdfjs detaches the buffer it is given, so always hand it a copy.
async function openPdf(data) {
    const pdfjs = await loadPdfjs();
    return pdfjs.getDocument({ data: new Uint8Array(data), isEvalSupported: false, verbosity: 0 }).promise;
}

/**
 * Reduce raw extracted PDF text to its canonical form: NFC, ligatures expanded, soft hyphens
 * removed, whitespace collapsed. Use this on externally extracted text (e.g. from `pdftotext`)
 * so it hashes identically to `extractPdfText` output.
 *
 * @param {string} text
 * @returns {string}
 */
export function canonicalizePdfText(text) {
    const folded = text
        .normalize('NFC')
        .replace(/[ﬀ-ﬆ]/g, (c) => LIGATURES[c])
        .replace(/\u00AD/g, '');
    return normalise(folded);
}

/**
 * Extract the canonical text of a PDF (pages in order, lines joined by single spaces).
 * Requires the optional peer dependency `pdfjs-dist`.
 *
 * @param {Uint8Array | ArrayBuffer} data
 * @returns {Promise<string>}
 */
export async function extractPdfText(data) {
    const doc = await openPdf(data);
    try {
        let raw = '';
        for (let n = 1; n <= doc.numPages; n++) {
            const page = await doc.getPage(n);
            const content = await page.getTextContent();
            for (const item of content.items) {
                if (typeof item.str !== 'string') continue;
                raw += item.str + (item.hasEOL ? '\n' : '');
            }
            raw += '\n';
        }
        return canonicalizePdfText(raw);
    } finally {
        await doc.loadingTask.destroy();
    }
}

function pickRef(data) {
    return {
        ipfsCid: data.ipfsCid,
        ...(data.chainId != null && { chainId: data.chainId }),
        ...(data.authority && { authority: data.authority }),
        ...(data.attestationIndex != null && { attestationIndex: data.attestationIndex }),
    };
}

function validateQuoteEntry(entry) {
    const proof = entry?.proofJson;
    if (typeof entry?.quote !== 'string' || typeof proof?.ipfsCid !== 'string' || !Array.isArray(proof.proof)) {
        throw new Error('Invalid Indelible quote entry. Expected { quote, proofJson: { ipfsCid, proof[] } }.');
    }
    return { quote: entry.quote, proofJson: proof };
}

/**
 * Validate and normalise a sidecar (`*.indelible.json`) document, also the format of the
 * embedded `indelible.json` attachment: an attestation ref plus an optional `quotes` array
 * of `{ quote, proofJson }`.
 *
 * @param {string | object} input JSON string or parsed object.
 * @returns {{ attestation: { ipfsCid: string, chainId?: number, authority?: string, attestationIndex?: number } | null,
 *             quotes: { quote: string, proofJson: object }[] }}
 */
export function parseSidecar(input) {
    const data = typeof input === 'string' ? JSON.parse(input) : input;
    if (!data || typeof data !== 'object') throw new Error('Invalid Indelible sidecar.');
    if (data.quotes !== undefined && !Array.isArray(data.quotes)) {
        throw new Error('Invalid Indelible sidecar: "quotes" must be an array.');
    }
    const attestation = typeof data.ipfsCid === 'string' ? pickRef(data) : null;
    const quotes = (data.quotes ?? []).map(validateQuoteEntry);
    if (!attestation && quotes.length === 0) {
        throw new Error('Invalid Indelible sidecar: expected ipfsCid and/or quotes.');
    }
    return { attestation, quotes };
}

/**
 * PDF counterpart of `extractPageData`: read the attestation ref and quote proofs embedded
 * as attachments. Returns null when the PDF carries no Indelible metadata. Malformed
 * attachments are skipped. Text is not returned — extract it with `extractPdfText`.
 *
 * @param {Uint8Array | ArrayBuffer} pdfBytes
 * @returns {Promise<{ attestation: object | null, quotes: { quote: string, proofJson: object }[] } | null>}
 */
export async function readIndelibleMetadata(pdfBytes) {
    const doc = await openPdf(pdfBytes);
    try {
        // Newer pdfjs returns a Map keyed by id with lazily loaded content; older returns a plain object.
        const raw = (await doc.getAttachments()) ?? {};
        const attachments = raw instanceof Map ? [...raw] : Object.entries(raw);
        const decoder = new TextDecoder();
        let attestation = null;
        const quotes = [];

        for (const [id, file] of attachments) {
            const name = file.filename ?? id;
            const isMain = name === INDELIBLE_ATTACHMENT;
            if (!isMain && !QUOTE_ATTACHMENT_PATTERN.test(name)) continue;
            try {
                const content = file.content ?? (await doc.getAttachmentContent(id));
                const json = JSON.parse(decoder.decode(content));
                if (isMain) {
                    const parsed = parseSidecar(json);
                    attestation = parsed.attestation;
                    quotes.push(...parsed.quotes);
                } else {
                    quotes.push(validateQuoteEntry(json));
                }
            } catch {
                // Skip malformed attachments.
            }
        }

        return attestation || quotes.length > 0 ? { attestation, quotes } : null;
    } finally {
        await doc.loadingTask.destroy();
    }
}

async function attachFiles(pdfBytes, files, cid) {
    const { PDFDocument, PDFName, PDFString } = await loadPdfLib();
    const pdfDoc = await PDFDocument.load(pdfBytes, { updateMetadata: false });
    const encoder = new TextEncoder();
    for (const { name, json, description } of files) {
        await pdfDoc.attach(encoder.encode(JSON.stringify(json)), name, {
            mimeType: 'application/json',
            description,
        });
    }
    if (cid) {
        pdfDoc.getInfoDict().set(PDFName.of('Indelible-CID'), PDFString.of(cid));
    }
    return pdfDoc.save();
}

async function quoteAttachment(entry) {
    const { quote, proofJson } = validateQuoteEntry(entry);
    const id = (await hexHashContent(quote)).slice(2, 14);
    return {
        name: `${QUOTE_ATTACHMENT_PREFIX}${id}.json`,
        json: { quote, proofJson },
        description: 'Indelible quote proof',
    };
}

/**
 * Embed the attestation ref (and optionally quote proofs) in a PDF as attachments, and
 * record the CID in the Info dictionary as `Indelible-CID`. Call once per PDF — repeated
 * calls add duplicate attachments.
 *
 * @param {Uint8Array | ArrayBuffer} pdfBytes
 * @param {{ attestationRef: { ipfsCid: string, chainId?: number, authority?: string, attestationIndex?: number },
 *           quotes?: { quote: string, proofJson: object }[] }} args
 * @returns {Promise<Uint8Array>}
 */
export async function embedIndelibleMetadata(pdfBytes, { attestationRef, quotes = [] }) {
    if (typeof attestationRef?.ipfsCid !== 'string') throw new Error('attestationRef.ipfsCid is required.');
    const files = [
        { name: INDELIBLE_ATTACHMENT, json: pickRef(attestationRef), description: 'Indelible attestation reference' },
        ...(await Promise.all(quotes.map(quoteAttachment))),
    ];
    return attachFiles(pdfBytes, files, attestationRef.ipfsCid);
}

/**
 * Embed a single quote proof in a PDF (the PDF equivalent of `data-indelible-quote`).
 *
 * @param {Uint8Array | ArrayBuffer} pdfBytes
 * @param {{ quote: string, proofJson: object }} entry
 * @returns {Promise<Uint8Array>}
 */
export async function embedQuoteProof(pdfBytes, entry) {
    return attachFiles(pdfBytes, [await quoteAttachment(entry)]);
}

/**
 * Commit phase for a PDF: extracts its canonical text and calls `commitAttestation`.
 * Wait out the reveal delay, call `revealAttestation`, then `finalizePdf`.
 *
 * @param {Omit<Parameters<typeof commitAttestation>[0], 'content'> & { pdfBytes: Uint8Array | ArrayBuffer }} args
 */
export async function commitPdf({ pdfBytes, ...rest }) {
    const content = await extractPdfText(pdfBytes);
    return commitAttestation({ ...rest, content });
}

/**
 * Produce the Indelible-tagged PDF and a sidecar after `revealAttestation`: proves each
 * quote against the PDF's canonical text and embeds the results.
 *
 * @param {{
 *   publicClient: import('viem').PublicClient,
 *   pdfBytes: Uint8Array | ArrayBuffer,
 *   commitResult: Awaited<ReturnType<typeof commitAttestation>>,
 *   revealResult: { attestationIndex: bigint },
 *   chainId?: number,
 *   quotes?: string[],
 *   disableSegmenting?: boolean,
 * }} args
 * @returns {Promise<{ pdfBytes: Uint8Array, sidecar: object }>}
 */
export async function finalizePdf({
    publicClient,
    pdfBytes,
    commitResult,
    revealResult,
    chainId,
    quotes = [],
    disableSegmenting = false,
}) {
    const text = await extractPdfText(pdfBytes);
    if ((await createRawCIDv1(text)) !== commitResult.ipfsCid) {
        throw new Error('PDF text no longer matches the committed attestation.');
    }

    const attestationRef = buildAttestationRef(commitResult, revealResult, chainId ?? publicClient.chain?.id);
    const entries = [];
    for (const quote of quotes) {
        const { proofJson } = await proveQuote({
            articleText: text,
            quote,
            authority: commitResult.authority,
            publicClient,
            chainId: attestationRef.chainId,
            disableSegmenting,
        });
        entries.push({ quote, proofJson });
    }

    return {
        pdfBytes: await embedIndelibleMetadata(pdfBytes, { attestationRef, quotes: entries }),
        sidecar: { ...attestationRef, quotes: entries },
    };
}

async function loadMetadata(pdfBytes, sidecar) {
    return sidecar != null ? parseSidecar(sidecar) : readIndelibleMetadata(pdfBytes);
}

function mismatch(detail, attestations = []) {
    return new VerificationResult([RESULT_CODE.UNVERIFIED], 'Content Mismatch', [detail], attestations);
}

/**
 * Verify a PDF against the chain. The CID is always recomputed from the PDF's own text, so
 * a ref that does not match the document yields UNVERIFIED. Metadata comes from `opts.sidecar`
 * if given, else the embedded attachments; with neither, the CID is looked up directly.
 *
 * @param {import('viem').PublicClient} publicClient
 * @param {Uint8Array | ArrayBuffer} pdfBytes
 * @param {{ sidecar?: string | object, authority?: `0x${string}`, taanqAddress?: `0x${string}` }} [opts]
 * @returns {Promise<VerificationResult>}
 */
export async function verifyPdf(publicClient, pdfBytes, opts = {}) {
    const meta = await loadMetadata(pdfBytes, opts.sidecar);
    const cid = await createRawCIDv1(await extractPdfText(pdfBytes));
    const ref = meta?.attestation ?? null;
    const authority = opts.authority ?? ref?.authority ?? null;
    const verifyOpts = { taanqAddress: opts.taanqAddress };

    if (ref && ref.ipfsCid !== cid) {
        return mismatch('The text of this PDF does not match the attested content.');
    }

    if (ref?.attestationIndex == null) {
        return verifyCid(publicClient, cid, authority, verifyOpts);
    }

    const verification = await verifyRef(publicClient, { ...ref, authority }, verifyOpts);
    const attestation = verification.attestations[verification.attestations.length - 1];
    if (attestation.cid !== cid) {
        return mismatch('The referenced attestation is for different content.', verification.attestations);
    }
    if (authority && attestation.authority.toLowerCase() !== authority.toLowerCase()) {
        return mismatch('The referenced attestation was published by a different authority.', verification.attestations);
    }
    return verification;
}

/**
 * Verify every quote proof embedded in (or supplied alongside) a PDF. `cidMatches` is true
 * only when the proof and the on-chain attestation both belong to this PDF's text.
 *
 * @param {import('viem').PublicClient} publicClient
 * @param {Uint8Array | ArrayBuffer} pdfBytes
 * @param {{ sidecar?: string | object, mode?: 'hard' | 'soft', taanqAddress?: `0x${string}` }} [opts]
 * @returns {Promise<{ quote: string, verification: VerificationResult, quoteText: string,
 *                     allProofsValid: boolean, quoteMatches: boolean, cidMatches: boolean }[]>}
 */
export async function verifyPdfQuotes(publicClient, pdfBytes, opts = {}) {
    const meta = await loadMetadata(pdfBytes, opts.sidecar);
    if (!meta || meta.quotes.length === 0) return [];

    const cid = await createRawCIDv1(await extractPdfText(pdfBytes));
    const results = [];
    for (const { quote, proofJson } of meta.quotes) {
        const result = await verifyQuoteProof(publicClient, proofJson, {
            taanqAddress: opts.taanqAddress,
            quote,
            mode: opts.mode ?? 'soft',
        });
        const attestation = result.verification.attestations[result.verification.attestations.length - 1];
        results.push({
            quote,
            ...result,
            cidMatches: proofJson.ipfsCid === cid && attestation?.cid === cid,
        });
    }
    return results;
}
