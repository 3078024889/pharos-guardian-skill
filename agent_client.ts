/**
 * GuardianSkill Client — How a Pharos AI Agent calls GuardianSkill
 *
 * This demonstrates an AI Agent autonomously:
 * 1. Calling GuardianSkill to audit a contract
 * 2. Paying 0.01 USDC automatically via x402 on Pharos
 * 3. Receiving structured risk data
 * 4. Deciding whether to proceed with a transaction
 */

import { config } from "dotenv";
config();

import { wrapFetchWithPayment, x402Client, decodePaymentResponseHeader } from "@x402/fetch";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";
import fs from "fs";

// ── Agent wallet setup ────────────────────────────────────────────────────────
const privateKey =
  process.env.EVM_PRIVATE_KEY ||
  (fs.existsSync(".private_key") ? fs.readFileSync(".private_key", "utf-8").trim() : null);

if (!privateKey) {
  console.error("❌ Set EVM_PRIVATE_KEY in .env or create .private_key file");
  console.error("   Get testnet PHRS at: https://pharos.xyz/faucet");
  process.exit(1);
}

const signer = privateKeyToAccount(privateKey as `0x${string}`);
console.log(`🤖 Agent wallet: ${signer.address}`);

// ── x402 client — wraps fetch to auto-pay when server returns 402 ─────────────
const x402 = new x402Client();
x402.register("eip155:688689", new ExactEvmScheme(signer)); // Pharos Atlantic Testnet

const fetchWithPayment = wrapFetchWithPayment(fetch, x402);

// ── GuardianSkill API ─────────────────────────────────────────────────────────
const SKILL_URL = process.env.GUARDIAN_SKILL_URL || "http://localhost:4022";

interface AuditResult {
  risk_score:       number;
  risk_level:       string;
  safe_to_transact: boolean;
  critical_count:   number;
  high_count:       number;
  recommendation:   string;
  findings:         Array<{ severity: string; title: string }>;
  audit_id:         string;
  duration_ms:      number;
}

/**
 * Audit a contract via GuardianSkill.
 * Automatically pays 0.01 USDC via x402 if server returns 402.
 */
async function auditWithGuardianSkill(
  contractAddress: string,
  sourceCode?: string
): Promise<AuditResult> {
  console.log(`\n🔍 Requesting audit for: ${contractAddress}`);
  console.log("💳 Will auto-pay 0.01 USDC via x402 if required...\n");

  const response = await fetchWithPayment(`${SKILL_URL}/skill/audit`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      contract_address: contractAddress,
      chain:            "pharos",
      ...(sourceCode && { source_code: sourceCode }),
    }),
  });

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`GuardianSkill error ${response.status}: ${err}`);
  }

  // Decode payment receipt if present
  const paymentHeader = response.headers.get("PAYMENT-RESPONSE");
  if (paymentHeader) {
    const receipt = decodePaymentResponseHeader(paymentHeader);
    console.log(`✅ Payment confirmed!`);
    console.log(`   Tx hash: ${receipt.transaction}`);
    console.log(`   Payer:   ${receipt.payer}`);
    console.log(`   Network: ${receipt.network}\n`);
  }

  return response.json();
}

/**
 * Quick safety check via GuardianSkill (cheaper — $0.005 USDC).
 */
async function quickCheck(contractAddress: string): Promise<{
  safe_to_transact: boolean;
  risk_level: string;
  risk_score: number;
}> {
  console.log(`⚡ Quick check for: ${contractAddress}`);

  const response = await fetchWithPayment(
    `${SKILL_URL}/skill/audit/quick?address=${contractAddress}`
  );

  if (!response.ok) throw new Error(`Quick check failed: ${response.status}`);
  return response.json();
}

// ── Agent Decision Logic ──────────────────────────────────────────────────────
async function agentDecideAndAct(contractAddress: string) {
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("  🤖 Pharos AI Agent — Security Check Flow");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

  // Step 1: Call GuardianSkill (auto-pays 0.01 USDC via x402)
  const audit = await auditWithGuardianSkill(contractAddress);

  // Step 2: Print results
  console.log("📊 Audit Results:");
  console.log(`   Risk Level:  ${audit.risk_level}`);
  console.log(`   Risk Score:  ${audit.risk_score}/100`);
  console.log(`   Critical:    ${audit.critical_count}`);
  console.log(`   High:        ${audit.high_count}`);
  console.log(`   Duration:    ${audit.duration_ms}ms`);
  console.log(`   Audit ID:    ${audit.audit_id}`);
  console.log(`\n💬 Recommendation: ${audit.recommendation}\n`);

  if (audit.findings.length > 0) {
    console.log("🔍 Top Findings:");
    audit.findings.slice(0, 5).forEach((f, i) => {
      console.log(`   ${i + 1}. [${f.severity}] ${f.title}`);
    });
    console.log();
  }

  // Step 3: Agent decision gate
  if (audit.safe_to_transact) {
    console.log("✅ AGENT DECISION: Contract is safe — proceeding with transaction");
    console.log("   → [TransactionSkill] would execute here in a full Agent pipeline");
  } else {
    console.log("⛔ AGENT DECISION: Contract is NOT safe — transaction aborted");
    console.log("   → [AlertSkill] would notify the user here in a full Agent pipeline");
  }

  console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  return audit;
}

// ── Main ──────────────────────────────────────────────────────────────────────
const contractAddress = process.argv[2] || "0x0000000000000000000000000000000000000001";

agentDecideAndAct(contractAddress).catch(err => {
  console.error("❌ Agent error:", err.message);
  process.exit(1);
});
