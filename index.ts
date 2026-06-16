/**
 * GuardianSkill — Pharos x402 Pay-Per-Audit Server
 *
 * A Pharos Skill that audits smart contracts for security vulnerabilities.
 * Uses the x402 protocol for pay-per-call billing on Pharos Atlantic Testnet.
 *
 * Pharos ChainID: 688689
 * Payment: 0.01 USDC per audit call
 */

import { config } from "dotenv";
config();

import express from "express";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { auditContract } from "./guardian_core.js";

// ── Environment ──────────────────────────────────────────────────────────────
const PAY_TO_ADDRESS  = process.env.PAY_TO_ADDRESS as `0x${string}`;
const FACILITATOR_URL = process.env.FACILITATOR_URL || "http://localhost:3000";
const USDC_ADDRESS    = process.env.USDC_ADDRESS || "0xE0BE08c77f415F577A1B3A9aD7a1Df1479564ec8";
const PORT            = parseInt(process.env.PORT || "4022", 10);

if (!PAY_TO_ADDRESS) {
  console.error("❌ Set PAY_TO_ADDRESS in .env");
  process.exit(1);
}

// ── x402 Setup ───────────────────────────────────────────────────────────────
const facilitatorClient = new HTTPFacilitatorClient({ url: FACILITATOR_URL });
const resourceServer    = new x402ResourceServer(facilitatorClient);

const evmScheme = new ExactEvmScheme();

// Register USDC on Pharos Atlantic Testnet (ChainID 688689)
evmScheme.registerMoneyParser(async (amount: number, network: string) => {
  if (network === "eip155:688689") {
    return {
      amount: Math.round(amount * 1e6).toString(), // USDC has 6 decimals
      asset:  USDC_ADDRESS,
      extra:  { token: "USDC", name: "USDC", version: "2" },
    };
  }
  return null;
});

resourceServer.register("eip155:688689", evmScheme);

// ── Express App ───────────────────────────────────────────────────────────────
const app = express();
app.use(express.json());

// x402 Payment Middleware — gate the /skill/audit endpoint at $0.01 per call
app.use(
  paymentMiddleware(
    {
      "POST /skill/audit": {
        accepts: {
          scheme:  "exact",
          price:   "0.01",           // $0.01 USDC per audit
          network: "eip155:688689",  // Pharos Atlantic Testnet
          payTo:   PAY_TO_ADDRESS,
        },
        description: "Smart contract security audit — AI-powered, pay-per-call",
        mimeType:    "application/json",
      },
      "GET /skill/audit/quick": {
        accepts: {
          scheme:  "exact",
          price:   "0.005",          // $0.005 for quick bytecode-only check
          network: "eip155:688689",
          payTo:   PAY_TO_ADDRESS,
        },
        description: "Quick contract safety check (bytecode heuristics)",
        mimeType:    "application/json",
      },
    },
    resourceServer
  )
);

// ── Skill Endpoints ───────────────────────────────────────────────────────────

/**
 * POST /skill/audit
 * Full AI-powered security audit (requires 0.01 USDC payment via x402)
 */
app.post("/skill/audit", async (req, res) => {
  const { contract_address, chain = "pharos", source_code } = req.body;

  if (!contract_address || !/^0x[0-9a-fA-F]{40}$/.test(contract_address)) {
    return res.status(400).json({
      error: "Invalid contract_address. Must be a valid 0x EVM address."
    });
  }

  console.log(`🔍 Auditing contract: ${contract_address} on ${chain}`);
  const startMs = Date.now();

  try {
    const result = await auditContract({
      contractAddress: contract_address,
      chain,
      sourceCode: source_code,
    });

    const response = {
      ...result,
      duration_ms: Date.now() - startMs,
      agent_version: "1.0.0",
      chain,
      pharos_network: "atlantic-testnet",
      chain_id: 688689,
    };

    console.log(`✅ Audit complete: ${result.risk_level} (score: ${result.risk_score})`);
    res.json(response);

  } catch (err: any) {
    console.error("Audit error:", err.message);
    res.status(500).json({ error: `Audit failed: ${err.message}` });
  }
});

/**
 * GET /skill/audit/quick?address=0x...
 * Fast bytecode heuristic check (requires 0.005 USDC via x402)
 */
app.get("/skill/audit/quick", async (req, res) => {
  const address = req.query.address as string;

  if (!address || !/^0x[0-9a-fA-F]{40}$/.test(address)) {
    return res.status(400).json({ error: "Invalid address parameter" });
  }

  try {
    const result = await auditContract({
      contractAddress: address,
      chain:           "pharos",
      quickMode:       true,
    });

    res.json({
      contract_address: address,
      safe_to_transact: result.safe_to_transact,
      risk_level:       result.risk_level,
      risk_score:       result.risk_score,
      quick_mode:       true,
      duration_ms:      result.duration_ms,
    });

  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ── Free Endpoints ────────────────────────────────────────────────────────────

/** GET /health — no payment required */
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    skill:  "guardian-security-audit",
    version: "1.0.0",
    pharos_chain_id: 688689,
    payment_token: "USDC",
    price_per_audit: "$0.01",
  });
});

/** GET /skill/manifest — return skill metadata */
app.get("/skill/manifest", (req, res) => {
  res.json({
    skill_id:    "guardian-security-audit",
    name:        "GuardianSkill",
    description: "Pay-per-audit AI security analysis for smart contracts",
    version:     "1.0.0",
    endpoints: {
      full_audit:  { method: "POST", path: "/skill/audit",       price: "$0.01 USDC" },
      quick_check: { method: "GET",  path: "/skill/audit/quick", price: "$0.005 USDC" },
    },
    pharos: { chain_id: 688689, network: "atlantic-testnet" },
    interface_docs: "https://github.com/3078024889/pharos-guardian-skill",
  });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("  🛡️  GuardianSkill — Pharos Security Audit Skill");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log(`✅ Listening on http://localhost:${PORT}`);
  console.log(`⛓️  Pharos Atlantic Testnet (ChainID: 688689)`);
  console.log(`💰 Payment address: ${PAY_TO_ADDRESS}`);
  console.log(`🪙  USDC: ${USDC_ADDRESS}`);
  console.log(`📋 Manifest: http://localhost:${PORT}/skill/manifest`);
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
});
