/**
 * GuardianSkill — x402 Facilitator
 * Handles on-chain payment verification and settlement on Pharos Atlantic Testnet.
 * ChainID: 688689
 */

import dotenv from "dotenv";
dotenv.config();

import express    from "express";
import { privateKeyToAccount }  from "viem/accounts";
import { createWalletClient, http, publicActions, defineChain } from "viem";
import { x402Facilitator }      from "@x402/core/facilitator";
import { toFacilitatorEvmSigner } from "@x402/evm";
import { ExactEvmScheme }       from "@x402/evm/exact/facilitator";

if (!process.env.EVM_PRIVATE_KEY) {
  console.error("❌ Set EVM_PRIVATE_KEY in .env");
  process.exit(1);
}

// Pharos Atlantic Testnet
const pharosAtlantic = defineChain({
  id: 688_689,
  name: "Pharos Atlantic Testnet",
  nativeCurrency: { name: "PHRS", symbol: "PHRS", decimals: 18 },
  rpcUrls: {
    default: { http: [process.env.PHAROS_RPC || "https://atlantic.dplabs-internal.com/"] }
  },
  testnet: true,
});

const account = privateKeyToAccount(process.env.EVM_PRIVATE_KEY as `0x${string}`);
const client  = createWalletClient({
  account,
  chain:     pharosAtlantic,
  transport: http(undefined, { timeout: 30_000 }),
}).extend(publicActions);

const signer = toFacilitatorEvmSigner({
  address:                  account.address,
  getCode:                  (args) => client.getCode(args),
  readContract:             (args) => client.readContract({ ...args, args: args.args || [] }),
  verifyTypedData:          (args) => client.verifyTypedData(args as any),
  writeContract:            (args) => client.writeContract({ ...args, args: args.args || [] }),
  sendTransaction:          (args) => client.sendTransaction(args),
  waitForTransactionReceipt:(args) => client.waitForTransactionReceipt(args),
});

const facilitator = new x402Facilitator();
facilitator.register(
  "eip155:688689",
  new ExactEvmScheme(signer, { deployERC4337WithEIP6492: true })
);

const app  = express();
const PORT = process.env.FACILITATOR_PORT || 3000;
app.use(express.json());

// Verify payment
app.post("/verify", async (req, res) => {
  try {
    const { paymentPayload, paymentRequirements } = req.body;
    const result = await facilitator.verify(paymentPayload, paymentRequirements);
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: (e as Error).message });
  }
});

// Settle on-chain
app.post("/settle", async (req, res) => {
  try {
    const { paymentPayload, paymentRequirements } = req.body;
    const result = await facilitator.settle(paymentPayload, paymentRequirements);
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: (e as Error).message });
  }
});

// Supported schemes
app.get("/supported", (req, res) => {
  res.json(facilitator.getSupported());
});

app.get("/health", (_, res) => res.json({ status: "ok", chain: "pharos-atlantic-688689" }));

app.listen(PORT, () => {
  console.log(`✅ Facilitator running on port ${PORT}`);
  console.log(`⛓️  Pharos Atlantic Testnet (ChainID: 688689)`);
  console.log(`👛 Facilitator wallet: ${account.address}`);
});
