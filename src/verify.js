import { StandardMerkleTree } from '@openzeppelin/merkle-tree';
import { fromHex } from 'viem';

import taanqAbi from './abi/taanqAbi.json' with { type: 'json' };
import { TAANQ_ADDRESS, RESULT_CODE, getPrimaryResultCode, getResultCodeCssClass } from './constants.js';
import { decodeCidToIpfsHash, getCIDFromRawDigest, prettifyTimestamp } from './utils.js';

/**
 * On-chain attestation record.
 */
export class Attestation {
    constructor(cid, qvHash, parentIpfsHash, authority, timestamp, revokedAt, index) {
        this.cid = cid;
        this.qvHash = qvHash;
        this.parentIpfsHash = parentIpfsHash;
        this.authority = authority;
        this.timestamp = timestamp;
        this.revokedAt = revokedAt;
        this.index = index;
    }
}

/**
 * Result of a CID verification check.
 */
export class VerificationResult {
    constructor(resultCode, headline, details, attestations) {
        this.resultCode = resultCode;
        this.headline = headline;
        this.details = details;
        this.attestations = attestations;
    }

    /**
     * The single highest-priority code from `resultCode`, suitable for
     * choosing UI styling. See `getPrimaryResultCode` for priority order.
     */
    get primaryResultCode() {
        return getPrimaryResultCode(this.resultCode);
    }

    /**
     * CSS class associated with the primary result code, e.g. `'result-verified'`.
     */
    get cssClass() {
        return getResultCodeCssClass(this.primaryResultCode);
    }
}

/**
 * Read `cidToAttestationIndices(ipfsHash, indexOfIndex)` from the taanq contract.
 *
 * @param {import('viem').PublicClient} publicClient
 * @param {`0x${string}`} ipfsHash bytes32 hex (raw SHA-256 digest of content)
 * @param {number|bigint} indexOfAttestationIndex
 * @param {{ taanqAddress?: `0x${string}` }} [opts]
 * @returns {Promise<bigint>} Attestation index, or 0n if none.
 */
export async function cidToAttestationIndices(publicClient, ipfsHash, indexOfAttestationIndex, opts = {}) {
    try {
        return await publicClient.readContract({
            address: opts.taanqAddress ?? TAANQ_ADDRESS,
            abi: taanqAbi,
            functionName: 'cidToAttestationIndices',
            args: [ipfsHash, indexOfAttestationIndex],
        });
    } catch {
        return 0n;
    }
}

/**
 * Read `cidAndAddressToAttestationIndices(ipfsHash, authority)` from the taanq contract.
 *
 * @param {import('viem').PublicClient} publicClient
 * @param {`0x${string}`} ipfsHash
 * @param {`0x${string}`} authority
 * @param {{ taanqAddress?: `0x${string}` }} [opts]
 * @returns {Promise<bigint>}
 */
export async function cidAndAddressToAttestationIndices(publicClient, ipfsHash, authority, opts = {}) {
    try {
        return await publicClient.readContract({
            address: opts.taanqAddress ?? TAANQ_ADDRESS,
            abi: taanqAbi,
            functionName: 'cidAndAddressToAttestationIndices',
            args: [ipfsHash, authority],
        });
    } catch {
        return 0n;
    }
}

function attestationFromRpc(rpcResponse, index) {
    const cid = getCIDFromRawDigest(fromHex(rpcResponse[0], 'bytes'));
    return new Attestation(
        cid,
        rpcResponse[1],
        rpcResponse[2],
        rpcResponse[3],
        rpcResponse[4],
        rpcResponse[5],
        index,
    );
}

/**
 * Fetch a single attestation by its global index.
 *
 * @param {import('viem').PublicClient} publicClient
 * @param {number|bigint} index
 * @param {{ taanqAddress?: `0x${string}` }} [opts]
 * @returns {Promise<Attestation>}
 */
export async function getAttestationByIndex(publicClient, index, opts = {}) {
    const rpcResponse = await publicClient.readContract({
        address: opts.taanqAddress ?? TAANQ_ADDRESS,
        abi: taanqAbi,
        functionName: 'attestations',
        args: [index],
    });
    return attestationFromRpc(rpcResponse, index);
}

/**
 * Verify using a plain reference object (as produced by `attestationToRef` / `verificationResultToRef`).
 * When `attestationIndex` is present the attestation is fetched directly by index; otherwise falls
 * back to a full CID lookup via `verifyCid`.
 *
 * @param {import('viem').PublicClient} publicClient
 * @param {{ ipfsCid: string, authority?: `0x${string}`, attestationIndex?: number }} ref
 * @param {{ taanqAddress?: `0x${string}` }} [opts]
 * @returns {Promise<VerificationResult>}
 */
export async function verifyRef(publicClient, ref, opts = {}) {
    if (ref.attestationIndex != null) {
        const attestation = await getAttestationByIndex(publicClient, ref.attestationIndex, opts);
        const isRevoked = attestation.revokedAt != 0;
        return new VerificationResult(
            isRevoked ? [RESULT_CODE.REVOKED] : [RESULT_CODE.VERIFIED],
            isRevoked ? 'Attestation Revoked' : 'Verified',
            isRevoked
                ? [`Revoked at ${prettifyTimestamp(attestation.revokedAt)}`]
                : [`Published by ${attestation.authority} at ${prettifyTimestamp(attestation.timestamp)}.`],
            [attestation],
        );
    }
    return verifyCid(publicClient, ref.ipfsCid, ref.authority ?? null, opts);
}

/**
 * Verify whether a given CID has been attested on-chain (optionally by a specific authority).
 *
 * @param {import('viem').PublicClient} publicClient
 * @param {string} cid base32 CIDv1 of the content
 * @param {?`0x${string}`} [authority] If provided, also verifies the named authority attested it.
 * @param {{ taanqAddress?: `0x${string}` }} [opts]
 * @returns {Promise<VerificationResult>}
 */
export async function verifyCid(publicClient, cid, authority = null, opts = {}) {
    const resultCode = [];
    const details = [];
    const ipfsHash = decodeCidToIpfsHash(cid);

    const firstAttestationIndex = await cidToAttestationIndices(publicClient, ipfsHash, 0, opts);

    if (firstAttestationIndex == 0) {
        resultCode.push(RESULT_CODE.NOT_FOUND);
        if (authority) {
            resultCode.push(RESULT_CODE.UNVERIFIED);
        }
        details.push('This text/CID has not yet been published to the Indelible Protocol.');
        return new VerificationResult(resultCode, 'No Attestation Found', details, []);
    }

    const firstAttestation = await getAttestationByIndex(publicClient, firstAttestationIndex, opts);

    if (authority) {
        let authorityAttestation;
        if (firstAttestation.authority.toLowerCase() != authority.toLowerCase()) {
            const authorityAttestationIndex = await cidAndAddressToAttestationIndices(
                publicClient,
                ipfsHash,
                authority,
                opts,
            );
            if (authorityAttestationIndex == 0) {
                resultCode.push(RESULT_CODE.UNVERIFIED);
                details.push(`This text/CID has not yet been published to the Indelible Protocol by ${authority}.`);
                return new VerificationResult(resultCode, 'Unverified', details, [firstAttestation]);
            }
            details.push(
                `It was first published to the Indelible Protocol by ${firstAttestation.authority} at ${prettifyTimestamp(firstAttestation.timestamp)}`,
            );
            authorityAttestation = await getAttestationByIndex(publicClient, authorityAttestationIndex, opts);
        } else {
            authorityAttestation = firstAttestation;
        }

        if (authorityAttestation.revokedAt != 0) {
            resultCode.push(RESULT_CODE.REVOKED);
            details.push(`It was revoked at ${prettifyTimestamp(authorityAttestation.revokedAt)}`);
            return new VerificationResult(resultCode, 'Attestation Revoked', details, [
                firstAttestation,
                authorityAttestation,
            ]);
        }
        resultCode.push(RESULT_CODE.VERIFIED);
        details.push(
            `This text/CID has been published to the Indelible Protocol by ${authorityAttestation.authority} at ${prettifyTimestamp(authorityAttestation.timestamp)}.`,
        );
        return new VerificationResult(resultCode, 'Verified', details, [firstAttestation, authorityAttestation]);
    }

    if (firstAttestation.revokedAt != 0) {
        resultCode.push(RESULT_CODE.REVOKED);
        details.push(`It was revoked at ${prettifyTimestamp(firstAttestation.revokedAt)}`);
    }
    resultCode.push(RESULT_CODE.VERIFIED);
    details.push(
        `This text/CID has been published to the Indelible Protocol by ${firstAttestation.authority} at ${prettifyTimestamp(firstAttestation.timestamp)}.`,
    );
    return new VerificationResult(resultCode, 'Attestation Found', details, [firstAttestation]);
}

/**
 * Verify a quote-proof JSON document (as produced by `proveQuote`) against the on-chain
 * attestation. Returns the verification result, the reconstructed quote text, and a flag
 * indicating whether every Merkle proof was valid.
 *
 * @param {import('viem').PublicClient} publicClient
 * @param {{ ipfsCid: string, authority?: `0x${string}`, attestationIndex?: number, proof: { value: [string, string], proof: string[] }[], chainId?: number }} proofData
 * @param {{ taanqAddress?: `0x${string}` }} [opts]
 * @returns {Promise<{ verification: VerificationResult, quoteText: string, allProofsValid: boolean }>}
 */
export async function verifyQuoteProof(publicClient, proofData, opts = {}) {
    if (!proofData || !proofData.ipfsCid || !Array.isArray(proofData.proof)) {
        throw new Error('Invalid proof data. Expected ipfsCid and proof array.');
    }

    let verification;
    if (proofData.attestationIndex != null) {
        const attestation = await getAttestationByIndex(publicClient, proofData.attestationIndex, opts);
        const isRevoked = attestation.revokedAt != 0;
        verification = new VerificationResult(
            isRevoked ? [RESULT_CODE.REVOKED] : [RESULT_CODE.VERIFIED],
            isRevoked ? 'Attestation Revoked' : 'Verified',
            isRevoked
                ? [`Revoked at ${prettifyTimestamp(attestation.revokedAt)}`]
                : [`Published by ${attestation.authority} at ${prettifyTimestamp(attestation.timestamp)}.`],
            [attestation],
        );
    } else {
        verification = await verifyCid(publicClient, proofData.ipfsCid, proofData.authority ?? null, opts);
    }

    const attestation = verification.attestations[verification.attestations.length - 1];
    const merkleRoot = attestation?.qvHash;

    const sortedProofs = [...proofData.proof].sort((a, b) => Number(a.value[0]) - Number(b.value[0]));

    let allProofsValid = Boolean(merkleRoot);
    if (merkleRoot) {
        for (const item of sortedProofs) {
            const valid = StandardMerkleTree.verify(merkleRoot, ['string', 'string'], item.value, item.proof);
            if (!valid) {
                allProofsValid = false;
                break;
            }
        }
    }

    const quoteText = sortedProofs.map((item) => item.value[1]).join('');

    return { verification, quoteText, allProofsValid };
}
