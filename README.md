# PoC — Bull SDK `open()`: `buyerReceive` not verified, tokens diverted

## What it proves

The Bull SDK (`bull.mjs`) claims:
> "Safety: the API server is not trusted with your wallet. Every transaction
> it returns is checked before it is sent."

`open()` checks only **buyer, seller and feeBps** from the `DealCreated`
event. It does NOT check `buyerReceive`, `sellToken`, `sellAmount`,
`payToken`, `payAmount` or `deadline` in the `createDeal` transaction the
API server returns. A compromised/malicious API server can rewrite
`buyerReceive` to an attacker address. The victim pays the full price, the
legitimate seller delivers real tokens, the swap settles — and the tokens go
to the attacker. The victim loses the entire payment and receives nothing.

Same root cause as the `lock()` PoC (SDK does not verify server-returned
transaction contents against user intent); different function, different
exploit path, independent impact.

## Run (local only — no real funds, no mainnet, no Bull infrastructure)

```bash
# 1. Start Anvil (Foundry) on port 8545
anvil --port 8545 --chain-id 31337

# 2. Run (from this directory)
node run-poc.mjs
```

What happens:
1. Deploys `MockERC20` (RealToken) and the **real** `BullEscrow` source
   (verbatim, verified on Sourcify chain 4663). The escrow is etched at its
   production address `0xd685d39E…` on Anvil because the SDK hardcodes the
   allowed escrow addresses in its guard; its constructor-set storage
   (`nextId = 1`, `_lock = 1`) is restored with `anvil_setStorageAt`.
   The fee quote is signed with a feeSigner key this PoC controls, exactly
   as the real backend would.
2. Seller holds 1,000 RealToken. Victim holds ETH.
3. Victim calls `bull.open({ seller, sellToken, sellAmount: "1000",
   payAsset: "eth", payAmount: "0.5" })` via the **real** SDK.
   The mock Bull API returns a `createDeal` with `buyerReceive = attacker`.
4. The SDK returns `dealId: 1` with **no error, no warning**.
5. Victim calls `bull.fund(dealId)` — pays 0.5 ETH into escrow.
6. Legit seller calls `fundTokens()` — the swap settles.

## Result (verified 16 Nov 2026)

```
SDK returned dealId: 1 — NO ERROR, NO WARNING about the tampered buyerReceive
on-chain deal buyerReceive: 0x5047… (attacker) — buyerReceive == attacker ? true
victim funded 0.5 ETH via bull.fund()
seller delivered 1,000 RealToken — swap settled
victim RealToken balance: 0
attacker RealToken balance: 1000
victim ETH after: 9999.495… (paid 0.5 ETH + gas)
EXPLOITED: victim paid 0.5 ETH and received 0 tokens; attacker received all 1,000 tokens.
```

## Files

- `bull-sdk.mjs` — verbatim copy of https://www.bull.family/sdk/bull.mjs
  (sha256 `b8abb874115915485012abd954e9a0ea9951d66b42edb84e84583b5f52d52a0c`)
- `mock-api.mjs` — malicious mock Bull API (localhost only); signs the fee
  quote with the PoC-controlled feeSigner, exactly like the real backend
- `run-poc.mjs` — the PoC driver (real SDK + real BullEscrow on Anvil)
- `chain/src/BullEscrow.sol` — verbatim BullEscrow source (Sourcify, 4663)
- `chain/src/Mocks.sol` — MockERC20
- `poc-result.json` — machine-readable result of the last run

## Do NOT publish yet

This PoC is prepared for the Bull bug-bounty report form (whose PoC field
asks for a LINK). It must be published (gist/repo) **only together with the
report submission**, after the user approves the draft — never before
(Bull's rules: no public disclosure until fixed). It contains no private
keys, no seed phrases, no real credentials: all wallets are throwaway keys
generated fresh on each run on a local Anvil chain.
