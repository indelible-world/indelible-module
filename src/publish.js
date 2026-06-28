import { keccak256, encodePacked, toHex, pad, parseAbi, namehash, hexToBytes } from 'viem';

import taanqAbi from './abi/taanqAbi.json' with { type: 'json' };
import ensAbi from './abi/ensAbi.json' with { type: 'json' };
import { TAANQ_ADDRESS, ENS_INDELIBLE_ADDRESS, MERKLE_SPLIT } from './constants.js';
import { buildTree, createRawCIDv1, dnsEncodeName, hexHashContent, getCIDFromRawDigest } from './utils.js';

const ENS_RESOLVER_ABI = parseAbi(['function setText(bytes32 node, string key, string value)']);

/**
 * Generate a random 32-byte salt as a `0x` hex string.
 * @returns {`0x${string}`}
 */
export function generateSalt() {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    return toHex(salt);
}

/**
 * Build the salted hash that gets sent during the commit phase.
 * @param {`0x${string}`} ipfsHash bytes32
 * @param {`0x${string}`} address  bytes20 — right-padded to bytes32
 * @param {`0x${string}`} salt     bytes32
 * @returns {`0x${string}`} keccak256(ipfsHash || padRight(address) || salt)
 */
export function buildSaltedHash(ipfsHash, address, salt) {
    const addressBytes32 = pad(address, { size: 32, dir: 'right' });
    return keccak256(
        encodePacked(['bytes32', 'bytes32', 'bytes32'], [ipfsHash, addressBytes32, salt]),
    );
}

/**
 * Commit phase of the commit/reveal attestation flow.
 * Sends `commit(saltedHash)` and returns everything required for the later reveal step.
 *
 * Throws if the commit transaction fails. Returns a `pendingCommit` tuple that should be
 * stored (e.g. localStorage) until the reveal delay has elapsed (~60s on most chains).
 *
 * @param {{
 *   walletClient: import('viem').WalletClient,
 *   publicClient: import('viem').PublicClient,
 *   content: string,
 *   account: `0x${string}`,
 *   authority?: `0x${string}`,
 *   parentIpfsHash?: `0x${string}`,
 *   taanqAddress?: `0x${string}`,
 * }} args
 * @returns {Promise<{
 *   txHash: `0x${string}`,
 *   pendingCommit: [
 *     `0x${string}`, `0x${string}`, `0x${string}`, `0x${string}`, `0x${string}`, `0x${string}`
 *   ],
 *   ipfsHash: `0x${string}`,
 *   qvHash: `0x${string}`,
 *   salt: `0x${string}`,
 *   saltedHash: `0x${string}`,
 *   authority: `0x${string}`,
 *   tree: import('@openzeppelin/merkle-tree').StandardMerkleTree<[string, string]>,
 * }>}
 */
export async function commitAttestation({
    walletClient,
    publicClient,
    content,
    account,
    authority,
    parentIpfsHash,
    taanqAddress = TAANQ_ADDRESS,
}) {
    const tree = buildTree(content);
    const ipfsHash = await hexHashContent(content);
    const qvHash = tree.root;
    const salt = generateSalt();
    const resolvedAuthority = authority || account;
    const resolvedParent = parentIpfsHash || `0x${'00'.repeat(32)}`;
    const saltedHash = buildSaltedHash(ipfsHash, resolvedAuthority, salt);

    const txHash = await walletClient.writeContract({
        address: taanqAddress,
        abi: taanqAbi,
        functionName: 'commit',
        args: [saltedHash],
    });

    const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
    if (receipt.status !== 'success') {
        throw new Error('Commit transaction failed');
    }

    const ipfsCid = getCIDFromRawDigest(hexToBytes(ipfsHash));

    return {
        txHash,
        pendingCommit: [saltedHash, salt, ipfsHash, qvHash, resolvedParent, resolvedAuthority],
        ipfsHash,
        ipfsCid,
        qvHash,
        salt,
        saltedHash,
        authority: resolvedAuthority,
        tree,
    };
}

/**
 * Build a ready-to-embed attestation reference from the results of
 * commitAttestation + revealAttestation.
 *
 * @param {{ ipfsCid: string, authority: `0x${string}` }} commitResult
 * @param {{ attestationIndex: bigint }} revealResult
 * @param {number} chainId
 * @returns {{ ipfsCid: string, chainId: number, authority: string, attestationIndex: number }}
 */
export function buildAttestationRef(commitResult, revealResult, chainId) {
    return {
        ipfsCid: commitResult.ipfsCid,
        chainId,
        authority: commitResult.authority,
        attestationIndex: Number(revealResult.attestationIndex),
    };
}

/**
 * Check whether a given authority has already attested a given CID/ipfsHash.
 * Returns the attestation index (0n if none).
 */
export async function getExistingAttestationIndex({
    publicClient,
    ipfsHash,
    authority,
    taanqAddress = TAANQ_ADDRESS,
}) {
    return publicClient.readContract({
        address: taanqAddress,
        abi: taanqAbi,
        functionName: 'cidAndAddressToAttestationIndices',
        args: [ipfsHash, authority],
    });
}

/**
 * Look up the current delegation record for an authority address.
 * Returns the raw `[delegate, timestamp]` tuple from the contract.
 */
export async function getDelegation({
    publicClient,
    authority,
    taanqAddress = TAANQ_ADDRESS,
}) {
    return publicClient.readContract({
        address: taanqAddress,
        abi: taanqAbi,
        functionName: 'delegations',
        args: [authority],
    });
}

/**
 * Reveal phase of the commit/reveal attestation flow.
 * Sends `reveal(...pendingCommit)` and returns the new attestation index.
 *
 * @param {{
 *   walletClient: import('viem').WalletClient,
 *   publicClient: import('viem').PublicClient,
 *   pendingCommit: [
 *     `0x${string}`, `0x${string}`, `0x${string}`, `0x${string}`, `0x${string}`, `0x${string}`
 *   ],
 *   account: `0x${string}`,
 *   taanqAddress?: `0x${string}`,
 * }} args
 * @returns {Promise<{ txHash: `0x${string}`, attestationIndex: bigint }>}
 */
export async function revealAttestation({
    walletClient,
    publicClient,
    pendingCommit,
    account,
    taanqAddress = TAANQ_ADDRESS,
}) {
    const txHash = await walletClient.writeContract({
        address: taanqAddress,
        abi: taanqAbi,
        functionName: 'reveal',
        args: pendingCommit,

    });

    const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
    if (receipt.status !== 'success') {
        throw new Error('Reveal transaction failed');
    }

    const ipfsHash = pendingCommit[2];
    const authority = pendingCommit[5];
    const attestationIndex = await publicClient.readContract({
        address: taanqAddress,
        abi: taanqAbi,
        functionName: 'cidAndAddressToAttestationIndices',
        args: [ipfsHash, authority],
    });

    return { txHash, attestationIndex };
}

/**
 * Call `revokeAttestation(attestationId)` on the taanq contract.
 */
export async function revokeAttestation({
    walletClient,
    publicClient,
    attestationId,
    account,
    taanqAddress = TAANQ_ADDRESS,
}) {
    const txHash = await walletClient.writeContract({
        address: taanqAddress,
        abi: taanqAbi,
        functionName: 'revokeAttestation',
        args: [BigInt(attestationId)]
    });

    const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
    if (receipt.status !== 'success') {
        throw new Error('Revoke transaction failed');
    }
    return { txHash };
}

/**
 * Set the child IPFS hash on an existing attestation, signifying that a new version of the
 * attested content exists. Only callable by the attestation's authority or an active delegate.
 *
 * @param {{
 *   walletClient: import('viem').WalletClient,
 *   publicClient: import('viem').PublicClient,
 *   attestationId: number | bigint,
 *   childIpfsHash: `0x${string}`,
 *   account: `0x${string}`,
 *   taanqAddress?: `0x${string}`,
 * }} args
 * @returns {Promise<{ txHash: `0x${string}` }>}
 */
export async function setChildIpfsHash({
    walletClient,
    publicClient,
    attestationId,
    childIpfsHash,
    account,
    taanqAddress = TAANQ_ADDRESS,
}) {
    const txHash = await walletClient.writeContract({
        address: taanqAddress,
        abi: taanqAbi,
        functionName: 'setChildIpfsHash',
        args: [BigInt(attestationId), childIpfsHash],
    });

    const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
    if (receipt.status !== 'success') {
        throw new Error('setChildIpfsHash transaction failed');
    }
    return { txHash };
}

/**
 * Delegate this authority's attestation rights to another address.
 */
export async function delegate({
    walletClient,
    publicClient,
    delegateAddress,
    account,
    taanqAddress = TAANQ_ADDRESS,
}) {
    const txHash = await walletClient.writeContract({
        address: taanqAddress,
        abi: taanqAbi,
        functionName: 'delegate',
        args: [delegateAddress]
    });

    const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
    if (receipt.status !== 'success') {
        throw new Error('Delegate transaction failed');
    }
    return { txHash };
}

/**
 * Revoke any active delegation from this authority.
 */
export async function revokeDelegation({
    walletClient,
    publicClient,
    account,
    taanqAddress = TAANQ_ADDRESS,
}) {
    const txHash = await walletClient.writeContract({
        address: taanqAddress,
        abi: taanqAbi,
        functionName: 'revokeDelegation',
        args: []
    });

    const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
    if (receipt.status !== 'success') {
        throw new Error('Revoke delegation transaction failed');
    }
    return { txHash };
}

/**
 * Build a quote-proof JSON document that proves a contiguous sub-string of `articleText`
 * is part of an attested article, without revealing the rest of the article.
 *
 * If `publicClient` is supplied, the function will additionally try to look up the
 * on-chain attestation index for the given (article, authority) pair and embed it
 * (along with `chainId`) in the resulting JSON for efficient verification.
 *
 * @param {{
 *   articleText: string,
 *   quote: string,
 *   authority: `0x${string}`,
 *   publicClient?: import('viem').PublicClient,
 *   chainId?: number,
 *   taanqAddress?: `0x${string}`,
 * }} args
 * @returns {Promise<{
 *   proofJson: {
 *     ipfsCid: string,
 *     authority: `0x${string}`,
 *     chainId?: number,
 *     attestationIndex?: number,
 *     proof: { value: [string, string], proof: string[] }[],
 *   },
 *   onChain: boolean,
 * }>}
 */
export async function proveQuote({
    articleText,
    quote,
    authority,
    publicClient,
    chainId,
    taanqAddress = TAANQ_ADDRESS,
}) {
    if (!articleText) throw new Error('articleText is required.');
    if (!quote) throw new Error('quote is required.');
    if (!authority) throw new Error('authority is required.');

    const quoteStart = articleText.indexOf(quote);
    if (quoteStart === -1) {
        throw new Error('Quote not found in the article text.');
    }
    const quoteEnd = quoteStart + quote.length;

    const firstChunk = Math.floor(quoteStart / MERKLE_SPLIT);
    const lastChunk = Math.floor((quoteEnd - 1) / MERKLE_SPLIT);

    const tree = buildTree(articleText);
    const matchingProofs = [];
    for (const [i, v] of tree.entries()) {
        const chunkIndex = parseInt(v[0], 10);
        if (chunkIndex >= firstChunk && chunkIndex <= lastChunk) {
            matchingProofs.push({ value: v, proof: tree.getProof(i) });
        }
    }

    const cid = await createRawCIDv1(articleText);

    let attestationIndex;
    let resolvedChainId = chainId;
    let onChain = false;
    if (publicClient) {
        try {
            const ipfsHash = await hexHashContent(articleText);
            const index = await publicClient.readContract({
                address: taanqAddress,
                abi: taanqAbi,
                functionName: 'cidAndAddressToAttestationIndices',
                args: [ipfsHash, authority],
            });
            if (index > 0n) {
                attestationIndex = Number(index);
                onChain = true;
                if (resolvedChainId == null && publicClient.chain) {
                    resolvedChainId = publicClient.chain.id;
                }
            }
        } catch {
            // Leave attestationIndex undefined — caller may surface a warning.
        }
    }

    const proofJson = {
        ipfsCid: cid,
        ...(resolvedChainId != null && { chainId: resolvedChainId }),
        authority,
        ...(attestationIndex != null && { attestationIndex }),
        proof: matchingProofs,
    };

    return { proofJson, onChain };
}

/**
 * Register an ENS name binding with the Indelible ENS contract.
 *
 * Optionally sets the `indelible-address` text record on the ENS resolver if it isn't
 * already set (requires the caller to own the ENS name).
 *
 * @param {{
 *   walletClient: import('viem').WalletClient,
 *   publicClient: import('viem').PublicClient,
 *   ensName: string,
 *   account: `0x${string}`,
 *   setIndelibleAddressIfMissing?: boolean,
 *   ensIndelibleAddress?: `0x${string}`,
 * }} args
 * @returns {Promise<{ txHash: `0x${string}`, setTextTxHash?: `0x${string}` }>}
 */
export async function registerEnsBinding({
    walletClient,
    publicClient,
    ensName,
    account,
    setIndelibleAddressIfMissing = true,
    ensIndelibleAddress = ENS_INDELIBLE_ADDRESS,
}) {
    const normalized = ensName.trim().toLowerCase();
    // ENSv2: treat any dot-separated string as a potential name (.eth, DNS
    // names, subdomains, …) rather than restricting to a fixed TLD.
    if (!normalized || !normalized.includes('.') || normalized.length < 3) {
        throw new Error('Invalid ENS name (e.g. yourname.eth).');
    }

    const dnsName = dnsEncodeName(normalized);
    const node = namehash(normalized);

    // 1. Check the name exists / is resolvable. With ENSv2 this goes through
    //    the Universal Resolver (handled internally by viem >= 2.35).
    const resolverAddr = await publicClient.getEnsResolver({ name: normalized });
    if (!resolverAddr) {
        throw new Error('No resolver set for this ENS name. Please configure a resolver first.');
    }

    // 2. Check whether the name is already bound to this account.
    const existingBindingIndex = await publicClient.readContract({
        address: ensIndelibleAddress,
        abi: ensAbi,
        functionName: 'nodeToBinding',
        args: [node],
    });

    if (existingBindingIndex > 0n) {
        const existingBinding = await publicClient.readContract({
            address: ensIndelibleAddress,
            abi: ensAbi,
            functionName: 'resolveIndelibleAddress',
            args: [dnsName, node],
        });
        if (existingBinding && existingBinding.toLowerCase() === account.toLowerCase()) {
            throw new Error('This ENS name is already bound to your address.');
        }
    }

    // 3. Check whether the `indelible-address` text record already points at
    //    this account. If it does, no setText is required.
    let setTextTxHash;
    const indelibleAddr = await publicClient.getEnsText({ name: normalized, key: 'indelible-address' });
    const recordMatches = indelibleAddr && indelibleAddr.toLowerCase() === account.toLowerCase();

    // 4. If the record is missing or points elsewhere, ensure the caller has
    //    the right to set records (owns the name) and set it.
    if (!recordMatches) {
        if (!setIndelibleAddressIfMissing) {
            throw new Error('The "indelible-address" text record is not set to your address on this ENS name.');
        }
        const owner = await publicClient.readContract({
            address: ensRegistryAddress,
            abi: ENS_REGISTRY_ABI,
            functionName: 'owner',
            args: [node],
        });
        if (owner || owner.toLowerCase() !== account.toLowerCase()) {
            throw new Error('You do not own this ENS name. Only the owner can set the indelible-address record.');
        }

        setTextTxHash = await walletClient.writeContract({
            address: resolverAddr,
            abi: ENS_RESOLVER_ABI,
            functionName: 'setText',
            args: [node, 'indelible-address', account]
        });
        const setTextReceipt = await publicClient.waitForTransactionReceipt({ hash: setTextTxHash });
        if (setTextReceipt.status !== 'success') {
            throw new Error('Failed to set indelible-address text record');
        }
    }

    // Finally register the binding on the Indelible ENS contract.
    const txHash = await walletClient.writeContract({
        address: ensIndelibleAddress,
        abi: ensAbi,
        functionName: 'registerEnsBinding',
        args: [dnsName]
    });

    const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
    if (receipt.status !== 'success') {
        throw new Error('ENS binding transaction failed');
    }

    return { txHash, ...(setTextTxHash && { setTextTxHash }) };
}
