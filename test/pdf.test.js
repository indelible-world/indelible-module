import test from 'node:test';
import assert from 'node:assert/strict';
import { PDFDocument, StandardFonts } from 'pdf-lib';
import { toHex } from 'viem';

import { RESULT_CODE } from '../src/constants.js';
import { buildTree, createRawCIDv1, decodeCidToIpfsHash } from '../src/utils.js';
import { proveQuote } from '../src/publish.js';
import {
    canonicalizePdfText,
    embedIndelibleMetadata,
    embedQuoteProof,
    extractPdfText,
    parseSidecar,
    readIndelibleMetadata,
    verifyPdf,
    verifyPdfQuotes,
} from '../src/pdf.js';

const AUTHORITY = '0x00000000000000000000000000000000000000aa';
const LINES = [
    'The quick brown fox jumps over the lazy dog.',
    'Pack my box with five dozen liquor jugs and',
    'sphinx of black quartz, judge my vow.',
];

async function makePdf(lines = LINES) {
    const doc = await PDFDocument.create();
    const font = await doc.embedFont(StandardFonts.Helvetica);
    const page = doc.addPage();
    lines.forEach((line, i) => page.drawText(line, { x: 40, y: 700 - i * 20, size: 12, font }));
    return doc.save();
}

// Minimal taanq mock: one attestation (index 1) for `text`, with the Merkle root of that text.
async function mockClient(text, { revokedAt = 0n } = {}) {
    const cid = await createRawCIDv1(text);
    const hash = decodeCidToIpfsHash(cid);
    const row = [hash, buildTree(text).root, toHex(new Uint8Array(32)), AUTHORITY, 1700000000n, revokedAt, toHex(new Uint8Array(32))];
    return {
        cid,
        async readContract({ functionName, args }) {
            if (functionName === 'attestations') return row;
            if (functionName === 'cidToAttestationIndices' && args[0] === hash && args[1] === 0) return 1n;
            if (functionName === 'cidAndAddressToAttestationIndices' && args[0] === hash) return 1n;
            return 0n;
        },
    };
}

test('canonicalizePdfText folds ligatures, soft hyphens and whitespace', () => {
    assert.equal(canonicalizePdfText('o\uFB03ce\u00AD  of\n\uFB01re'), 'office of fire');
});

test('extractPdfText is stable across metadata embedding', async () => {
    const pdf = await makePdf();
    const text = await extractPdfText(pdf);
    assert.equal(text, LINES.join(' '));

    const tagged = await embedIndelibleMetadata(pdf, { attestationRef: { ipfsCid: await createRawCIDv1(text) } });
    assert.equal(await extractPdfText(tagged), text);
});

test('parseSidecar validates input', () => {
    assert.throws(() => parseSidecar({}));
    assert.throws(() => parseSidecar({ ipfsCid: 'x', quotes: 'nope' }));
    assert.throws(() => parseSidecar({ ipfsCid: 'x', quotes: [{ quote: 'a' }] }));
    assert.equal(parseSidecar('{"ipfsCid":"x"}').attestation.ipfsCid, 'x');
});

test('embedded metadata round-trips and verifies end to end', async () => {
    const pdf = await makePdf();
    const text = await extractPdfText(pdf);
    const client = await mockClient(text);

    const quote = 'brown fox ... lazy dog';
    const { proofJson } = await proveQuote({ articleText: text, quote, authority: AUTHORITY });
    const ref = { ipfsCid: client.cid, chainId: 11155111, authority: AUTHORITY, attestationIndex: 1 };

    const tagged = await embedIndelibleMetadata(pdf, { attestationRef: ref, quotes: [{ quote, proofJson }] });
    const meta = await readIndelibleMetadata(tagged);
    assert.equal(meta.attestation.attestationIndex, 1);
    assert.equal(meta.quotes.length, 1);

    const result = await verifyPdf(client, tagged);
    assert.deepEqual(result.resultCode, [RESULT_CODE.VERIFIED]);

    const [q] = await verifyPdfQuotes(client, tagged);
    assert.ok(q.allProofsValid && q.quoteMatches && q.cidMatches);
});

test('embedQuoteProof adds a quote without an attestation ref', async () => {
    const pdf = await makePdf();
    const text = await extractPdfText(pdf);
    const client = await mockClient(text);
    const quote = 'liquor jugs';
    const { proofJson } = await proveQuote({ articleText: text, quote, authority: AUTHORITY });

    const tagged = await embedQuoteProof(pdf, { quote, proofJson });
    const meta = await readIndelibleMetadata(tagged);
    assert.equal(meta.attestation, null);
    const [q] = await verifyPdfQuotes(client, tagged);
    assert.ok(q.allProofsValid && q.quoteMatches);
});

test('a PDF with no metadata yields null and falls back to CID lookup', async () => {
    const pdf = await makePdf();
    assert.equal(await readIndelibleMetadata(pdf), null);
    const client = await mockClient(await extractPdfText(pdf));
    const result = await verifyPdf(client, pdf);
    assert.ok(result.resultCode.includes(RESULT_CODE.VERIFIED));
});

test('third-party PDF verifies through a sidecar without being modified', async () => {
    const pdf = await makePdf();
    const text = await extractPdfText(pdf);
    const client = await mockClient(text);
    const quote = 'sphinx of black quartz';
    const { proofJson } = await proveQuote({ articleText: text, quote, authority: AUTHORITY });
    const sidecar = { ipfsCid: client.cid, authority: AUTHORITY, attestationIndex: 1, quotes: [{ quote, proofJson }] };

    const result = await verifyPdf(client, pdf, { sidecar });
    assert.deepEqual(result.resultCode, [RESULT_CODE.VERIFIED]);
    const [q] = await verifyPdfQuotes(client, pdf, { sidecar });
    assert.ok(q.allProofsValid && q.quoteMatches && q.cidMatches);
});

test('tampered PDF text is reported as a mismatch', async () => {
    const original = await makePdf();
    const client = await mockClient(await extractPdfText(original));
    const sidecar = { ipfsCid: client.cid, authority: AUTHORITY, attestationIndex: 1 };

    const tampered = await makePdf([LINES[0].replace('quick', 'slow'), LINES[1], LINES[2]]);
    const result = await verifyPdf(client, tampered, { sidecar });
    assert.deepEqual(result.resultCode, [RESULT_CODE.UNVERIFIED]);
});

test('a quote proof from a different document does not match this PDF', async () => {
    const pdf = await makePdf();
    const client = await mockClient(await extractPdfText(pdf));
    const otherText = 'A completely different document that was also attested.';
    const quote = 'different document';
    const { proofJson } = await proveQuote({ articleText: otherText, quote, authority: AUTHORITY });

    const [q] = await verifyPdfQuotes(client, pdf, { sidecar: { quotes: [{ quote, proofJson }] } });
    assert.equal(q.cidMatches, false);
});

test('revoked attestation is reported', async () => {
    const pdf = await makePdf();
    const client = await mockClient(await extractPdfText(pdf), { revokedAt: 1800000000n });
    const sidecar = { ipfsCid: client.cid, authority: AUTHORITY, attestationIndex: 1 };
    const result = await verifyPdf(client, pdf, { sidecar });
    assert.deepEqual(result.resultCode, [RESULT_CODE.REVOKED]);
});
