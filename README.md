# 🛡️ GuardianSkill — Smart Contract Security Audit Skill for Pharos

> A reusable, composable Pharos Skill that gives any AI Agent the ability to audit smart contracts for security vulnerabilities — with pay-per-call billing via the **x402 protocol** on Pharos Atlantic Testnet.

[![Pharos](https://img.shields.io/badge/Pharos-Atlantic%20Testnet-blue)](https://pharos.xyz)
[![x402](https://img.shields.io/badge/Payment-x402-orange)](https://x402.org)
[![ChainID](https://img.shields.io/badge/ChainID-688689-green)](https://pharos.xyz)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What is GuardianSkill?

GuardianSkill is a **Pharos Skill** — a standardized, reusable module that any Pharos AI Agent can call to check whether a smart contract is safe before transacting.

**The core problem it solves:**
AI Agents operating in DeFi are blind to contract security. Without a security check, an Agent can:
- Send funds to a reentrancy-vulnerable contract and lose everything
- Interact with a honeypot that accepts deposits but blocks withdrawals
- Call a contract with a hidden `SELFDESTRUCT` that drains the Agent's wallet

GuardianSkill gives every Pharos Agent a **security conscience** — one API call, instant structured risk data, automatic x402 payment.

---

## Architecture

```
AI Agent (Pharos)
      │
      │  POST /skill/audit
      │  [x402: auto-pays 0.01 USDC on Pharos ChainID 688689]
      ▼
GuardianSkill Server
      │
      ├── [1] Fetch bytecode from Pharos RPC
      │         pharosClient.getBytecode(address)
      │
      ├── [2] Bytecode Heuristic Analysis
      │         SELFDESTRUCT (0xff) → HIGH
      │         DELEGATECALL (0xf4) → MEDIUM
      │         tx.origin (0x32)   → MEDIUM
      │         Empty bytecode     → CRITICAL
      │
      ├── [3] LLM Semantic Analysis (if source code provided)
      │         OpenAI-compatible API (any LLM)
      │         Detects: reentrancy, oracle manipulation,
      │                  flash loan vectors, honeypot logic
      │
      └── [4] Structured JSON Response
                risk_score:       0-100
                risk_level:       SAFE/LOW/MEDIUM/HIGH/CRITICAL
                safe_to_transact: true/false  ← Agent gates on this
                findings:         [...detailed vulnerability list]
                recommendation:   "one-line agent action"
```

---

## x402 Payment Flow

GuardianSkill uses the **x402 protocol** for trustless, pay-per-call billing on Pharos:

```
Agent sends POST /skill/audit
          ↓
Server returns HTTP 402 + payment instructions
(0.01 USDC, Pharos ChainID 688689)
          ↓
Agent's x402 client auto-signs & sends USDC payment on Pharos
          ↓
Facilitator verifies payment on-chain
          ↓
Server delivers audit results (HTTP 200)
          ↓
PAYMENT-RESPONSE header contains tx_hash proof
```

**Price:** `0.01 USDC` per full audit | `0.005 USDC` per quick check
**Token:** USDC on Pharos Atlantic Testnet (`0xE0BE08c77f415F577A1B3A9aD7a1Df1479564ec8`)
**Chain:** Pharos Atlantic Testnet, ChainID `688689`

---

## Skill Interface

### Input

```json
{
  "contract_address": "0x...",
  "chain": "pharos",
  "source_code": "// optional Solidity source for deeper analysis"
}
```

### Output

```json
{
  "risk_score":       72,
  "risk_level":       "HIGH",
  "safe_to_transact": false,
  "critical_count":   0,
  "high_count":       2,
  "medium_count":     1,
  "low_count":        3,
  "findings": [
    {
      "id":             "BC-001",
      "severity":       "HIGH",
      "category":       "selfdestruct",
      "title":          "SELFDESTRUCT opcode detected",
      "description":    "...",
      "recommendation": "Ensure SELFDESTRUCT is gated by onlyOwner",
      "source":         "bytecode"
    }
  ],
  "recommendation":  "⚠️ HIGH RISK. Transaction not recommended.",
  "safe_to_transact": false,
  "audit_id":         "pharos-audit-1718000000-abc123",
  "duration_ms":      1240
}
```

---

## Composability — Chain With Other Skills

GuardianSkill is designed to be chained:

```typescript
// Agent pre-flight security check
const audit = await callSkill("guardian-security-audit", {
  contract_address: targetContract
});

if (audit.safe_to_transact) {
  // Chain into TransactionSkill
  await callSkill("execute-transaction", { to: targetContract, value: amount });
} else {
  // Chain into AlertSkill
  await callSkill("send-alert", {
    message: `Contract ${targetContract} flagged: ${audit.risk_level}`,
    user:    agentOwner
  });
}
```

**Any Pharos Agent handling DeFi, payments, or RWA can integrate GuardianSkill as a pre-flight safety check.**

---

## Quick Start

### Prerequisites

```bash
node >= 18
npm install
cp .env.example .env
# Fill in PRIVATE_KEY, PAY_TO_ADDRESS, OPENAI_API_KEY
```

Get testnet PHRS: https://pharos.xyz/faucet

### Run the Skill Server

```bash
npm run server
# ✅ Listening on http://localhost:4022
# ⛓️  Pharos Atlantic Testnet (ChainID: 688689)
```

### Run the Facilitator (in another terminal)

```bash
npm run facilitator
# ✅ Facilitator running on port 3000
```

### Call the Skill as an Agent

```bash
npm run client 0xYourContractAddress
# 🤖 Agent wallet: 0x...
# 🔍 Requesting audit for: 0x...
# 💳 Will auto-pay 0.01 USDC via x402...
# ✅ Payment confirmed! Tx hash: 0x...
# 📊 Risk Level: HIGH | Score: 72/100
# ⛔ AGENT DECISION: Transaction aborted
```

### Run Tests

```bash
npm test
```

---

## Project Structure

```
pharos-guardian-skill/
├── server/
│   ├── index.ts          ← x402 Express server (Skill endpoint)
│   ├── guardian_core.ts  ← Audit engine (bytecode + LLM)
│   └── facilitator.ts    ← x402 Facilitator (on-chain settlement)
├── client/
│   └── agent_client.ts   ← Example AI Agent using the Skill
├── skill/
│   └── skill_manifest.json ← Pharos Skill metadata
├── test/
│   └── skill.test.ts     ← Integration tests
├── .env.example
├── package.json
└── README.md
```

---

## Why Pharos for GuardianSkill?

| Feature | Pharos | Other Chains |
|---|---|---|
| TPS | 30,000 | < 5,000 |
| Finality | Sub-second | 2–15 seconds |
| x402 micropayments | ✅ Native | ❌ Too slow/expensive |
| EVM compatible | ✅ | Varies |
| AI Agent infrastructure | ✅ Built-in | ❌ |

**x402 on Pharos** makes `$0.01` per audit genuinely viable — confirmed in < 1 second, at < $0.001 in gas.

---

## Built for Pharos Skill-to-Agent Hackathon

This Skill is a Phase 1 submission for the **Pharos × Anvita Flow Skill-to-Agent Dual Cascade Hackathon**.

Phase 2 (Agent Arena): GuardianSkill will be integrated into a full Pharos AI Agent that autonomously monitors DeFi protocols, audits contracts before every transaction, and sends alerts when new vulnerabilities are detected.

---

## License

MIT
