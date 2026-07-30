# indelible

JavaScript client library for the [Indelible Standard](https://indelible.world): on-chain
content attestations, delegation, ENS bindings, and Merkle-based quote proofs.

This package extracts the core logic from the [`indelible-static`](https://github.com/indelible-world/indelible-static)
front-end into a framework-agnostic library you can use from any browser app, Node script,
or back-end service.

## Installation

```bash
npm install indelible viem
```

`viem` is a peer dependency — bring your own version (`^2.0.0`).

## Quick start

### Verify a CID

```js
import { createPublicClient, http } from 'viem';
import { sepolia } from 'viem/chains';
import { verifyCid } from 'indelible';

const publicClient = createPublicClient({
    chain: sepolia,
    transport: http(),
});

const result = await verifyCid(publicClient, 'bafkrei...');
console.log(result.headline, result.details);
```

### Verify a quote proof JSON

```js
import { verifyQuoteProof } from 'indelible';

const proofData = JSON.parse(await file.text());
const { verification, quoteText, allProofsValid } = await verifyQuoteProof(
    publicClient,
    proofData,
);

// Optionally check a displayed quote against the proven text. Defaults to
// 'hard' (verbatim substring). Use 'soft' to allow ellipses ("...", "…") and
// bracketed insertions ("[sic]") inside the quote — each literal segment must
// then appear in the proven text, in order.
const { quoteMatches } = await verifyQuoteProof(publicClient, proofData, {
    quote: displayedQuote,
    mode: 'soft',
});
```

### Commit + reveal an attestation

```js
import { createWalletClient, createPublicClient, custom } from 'viem';
import { sepolia } from 'viem/chains';
import { commitAttestation, revealAttestation } from 'indelible';

const walletClient = createWalletClient({
    account,
    chain: sepolia,
    transport: custom(window.ethereum),
});
const publicClient = createPublicClient({ chain: sepolia, transport: custom(window.ethereum) });

const { pendingCommit } = await commitAttestation({
    walletClient,
    publicClient,
    content: 'Hello, world.',
    account,
});

// Wait for the chain's commit/reveal delay (≈60s) before calling reveal:
const { attestationIndex } = await revealAttestation({
    walletClient,
    publicClient,
    pendingCommit,
    account,
});
```

### Generate a quote proof

```js
import { proveQuote, downloadJson } from 'indelible';

const { proofJson, onChain } = await proveQuote({
    articleText,
    quote,               // may contain "...", "…", or "[insertions]" — each
                         // segment around a gap is proven in order
    authority,
    publicClient,        // optional — embeds chainId + attestationIndex when found
});
downloadJson(proofJson, 'quote-proof.json'); // browser only
```

## API surface

### Constants — `indelible/constants`
- `TAANQ_ADDRESS`, `ENS_INDELIBLE_ADDRESS`, `ENS_REGISTRY_ADDRESS`
- `MERKLE_SPLIT` — chunk size used for Merkle quote proofs (46 chars)
- `RESULT_CODE` — `{ NOT_FOUND, VERIFIED, UNVERIFIED, REVOKED, WARNING }`

### Utilities — `indelible/utils`
- `hashContent(data)` / `hexHashContent(data)` — SHA-256 of bytes/string
- `createRawCIDv1(data)` — base32 CIDv1 of content
- `getCIDFromHash(hash)` / `getCIDFromRawDigest(bytes)` — CID from raw digest
- `decodeCidToIpfsHash(cidStr)` — extract bytes32 hex from a CID
- `buildTree(text)` — Merkle tree of fixed-size text chunks
- `dnsEncodeName(name)` — DNS wire-format encoding for ENS contracts
- `prettifyTimestamp(ts)` — formatted local time string
- `downloadJson(data, filename)` — browser file download

### Verification — `indelible/verify`
- `verifyCid(publicClient, cid, authority?)` → `VerificationResult`
- `verifyQuoteProof(publicClient, proofData, { quote?, mode? })` → `{ verification, quoteText, allProofsValid, quoteMatches? }`
- `quoteMatchesProvenText(quote, provenText, { mode? })` — `'hard'` (default, verbatim) or `'soft'` (allows `...`/`…`/`[…]` gaps)
- `getAttestationByIndex(publicClient, index)`
- `cidToAttestationIndices`, `cidAndAddressToAttestationIndices`
- Classes: `Attestation`, `VerificationResult`

### Writes & publishing — `indelible/publish`
- `commitAttestation({ walletClient, publicClient, content, account, authority?, parentIpfsHash? })`
- `revealAttestation({ walletClient, publicClient, pendingCommit, account })`
- `revokeAttestation({ walletClient, publicClient, attestationId, account })`
- `delegate({ walletClient, publicClient, delegateAddress, account })`
- `revokeDelegation({ walletClient, publicClient, account })`
- `proveQuote({ articleText, quote, authority, publicClient?, chainId? })`
- `registerEnsBinding({ walletClient, publicClient, ensName, account })`
- `getExistingAttestationIndex({ publicClient, ipfsHash, authority })`
- `getDelegation({ publicClient, authority })`
- `generateSalt()`, `buildSaltedHash(ipfsHash, address, salt)`

### ABIs
- `indelible/abi/taanq` — taanq attestation contract ABI (JSON)
- `indelible/abi/ens`   — Indelible ENS contract ABI (JSON)

## Notes

- All write functions take a viem `walletClient` + `publicClient`. The library does not
  bundle wallet discovery (EIP-6963) or chain switching — those concerns live in the host app.
- The commit phase emits a `pendingCommit` tuple — persist it (e.g. `localStorage`) until
  the contract's reveal delay elapses, then pass it to `revealAttestation`.
- `downloadJson` is a browser-only convenience; call sites in Node should serialize JSON
  themselves.

## License

MIT
