/**
 * GuardianSkill Core — Audit Engine
 * Standalone audit engine for Pharos smart contracts.
 * Two analysis modes:
 *   1. Full: bytecode heuristics + LLM semantic analysis
 *   2. Quick: bytecode heuristics only (faster, cheaper)
 */

import { createPublicClient, http } from "viem";
import { defineChain } from "viem";
import OpenAI from "openai";

// ── Pharos Atlantic Testnet Chain Definition ──────────────────────────────────
export const pharosAtlantic = defineChain({
  id: 688689,
  name: "Pharos Atlantic Testnet",
  nativeCurrency: { name: "PHRS", symbol: "PHRS", decimals: 18 },
  rpcUrls: {
    default: { http: [process.env.PHAROS_RPC || "https://atlantic.dplabs-internal.com/"] },
  },
  testnet: true,
});

// ── Types ─────────────────────────────────────────────────────────────────────
export interface AuditInput {
  contractAddress: string;
  chain?:          string;
  sourceCode?:     string;
  quickMode?:      boolean;
}

export interface Finding {
  id:             string;
  severity:       "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  category:       string;
  title:          string;
  description:    string;
  recommendation: string;
  source:         "bytecode" | "llm";
}

export interface AuditResult {
  contract_address: string;
  risk_score:       number;
  risk_level:       "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  safe_to_transact: boolean;
  critical_count:   number;
  high_count:       number;
  medium_count:     number;
  low_count:        number;
  findings:         Finding[];
  recommendation:   string;
  audit_id:         string;
  duration_ms:      number;
}

// ── Severity scoring ──────────────────────────────────────────────────────────
const SEV_SCORE: Record<string, number> = {
  CRITICAL: 40, HIGH: 20, MEDIUM: 8, LOW: 2, INFO: 0,
};

// ── Pharos RPC Client ─────────────────────────────────────────────────────────
const pharosClient = createPublicClient({
  chain:     pharosAtlantic,
  transport: http(),
});

// ── Bytecode Heuristic Analysis ───────────────────────────────────────────────
function analyzeBytecode(bytecode: string): Finding[] {
  const findings: Finding[] = [];
  const bc = bytecode.toLowerCase().replace("0x", "");

  // SELFDESTRUCT opcode (0xff)
  if (bc.includes("ff")) {
    findings.push({
      id: "BC-001", severity: "HIGH", category: "selfdestruct",
      title: "SELFDESTRUCT opcode detected",
      description: "Contract contains SELFDESTRUCT (0xff). If access control is missing, an attacker could destroy the contract and steal all ETH.",
      recommendation: "Ensure SELFDESTRUCT is protected by strict access control (onlyOwner). Consider removing it entirely.",
      source: "bytecode",
    });
  }

  // DELEGATECALL opcode (0xf4)
  if (bc.includes("f4")) {
    findings.push({
      id: "BC-002", severity: "MEDIUM", category: "delegatecall",
      title: "DELEGATECALL opcode detected",
      description: "Contract uses DELEGATECALL. If the target address is user-controlled, this allows arbitrary code execution in the contract's storage context.",
      recommendation: "Ensure DELEGATECALL targets are hardcoded or validated against an allowlist. Never use msg.data to derive the target address.",
      source: "bytecode",
    });
  }

  // tx.origin usage pattern (common honeypot signature)
  // ORIGIN opcode is 0x32
  if (bc.includes("32")) {
    findings.push({
      id: "BC-003", severity: "MEDIUM", category: "tx-origin",
      title: "tx.origin usage detected",
      description: "Contract appears to use tx.origin for authorization. This is exploitable via phishing: an attacker can trick the original signer into calling a malicious contract that then calls this contract with elevated privileges.",
      recommendation: "Replace tx.origin with msg.sender for authorization checks.",
      source: "bytecode",
    });
  }

  // Very short bytecode — possible proxy or minimal contract
  if (bc.length < 100 && bc.length > 0) {
    findings.push({
      id: "BC-004", severity: "INFO", category: "minimal-bytecode",
      title: "Minimal bytecode — possible proxy contract",
      description: "Contract bytecode is very short, suggesting this may be a proxy that delegates all logic elsewhere. The actual risk depends on the implementation contract.",
      recommendation: "Identify and audit the implementation contract this proxy delegates to.",
      source: "bytecode",
    });
  }

  // Empty bytecode (EOA or self-destructed)
  if (bc.length === 0 || bc === "") {
    findings.push({
      id: "BC-000", severity: "CRITICAL", category: "no-code",
      title: "No bytecode at this address",
      description: "The address has no deployed contract. It may be an EOA (regular wallet), a self-destructed contract, or a wrong address. Transacting with this address as a contract will fail or lose funds.",
      recommendation: "Verify the contract address. Do NOT send value expecting contract logic to execute.",
      source: "bytecode",
    });
  }

  return findings;
}

// ── LLM Semantic Analysis ─────────────────────────────────────────────────────
async function analyzeLLM(
  contractAddress: string,
  sourceCode: string,
  bytecodeFindings: Finding[]
): Promise<Finding[]> {
  const apiKey = process.env.OPENAI_API_KEY || process.env.LLM_API_KEY;
  if (!apiKey) {
    console.warn("No LLM API key set — skipping semantic analysis");
    return [];
  }

  const openai = new OpenAI({
    apiKey,
    baseURL: process.env.LLM_BASE_URL, // Supports any OpenAI-compatible endpoint
  });

  const staticSummary = bytecodeFindings
    .map(f => `[${f.severity}] ${f.category}: ${f.title}`)
    .join("\n");

  const prompt = `You are an expert smart contract security auditor. Analyze this Solidity contract for security vulnerabilities.

CONTRACT ADDRESS: ${contractAddress}
CHAIN: Pharos Atlantic Testnet (ChainID 688689, EVM-compatible)

SOURCE CODE:
\`\`\`solidity
${sourceCode.slice(0, 5000)}
\`\`\`

BYTECODE ANALYSIS ALREADY FOUND:
${staticSummary || "No bytecode findings"}

Find ADDITIONAL vulnerabilities the bytecode scan missed, especially:
1. Reentrancy attacks (state updated after external calls)
2. Integer overflow/underflow edge cases
3. Access control missing or insufficient (functions that should be protected)
4. Flash loan attack vectors in DeFi logic
5. Front-running vulnerabilities
6. Oracle manipulation risks
7. Business logic flaws (economic attacks)
8. Denial of service vectors
9. Honeypot patterns (withdraw functions that always revert)
10. Unsafe ERC20 patterns (missing return value checks)

Respond ONLY with a valid JSON array. Each item must have:
{
  "id": "AI-001",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "category": "short-slug",
  "title": "Brief title",
  "description": "Detailed explanation",
  "recommendation": "How to fix it",
  "source": "llm"
}

If no additional vulnerabilities found, return: []
Return ONLY the JSON array, no markdown, no explanation.`;

  try {
    const completion = await openai.chat.completions.create({
      model:       process.env.LLM_MODEL || "gpt-4o-mini",
      messages:    [{ role: "user", content: prompt }],
      temperature: 0.1,
      max_tokens:  2000,
    });

    let content = completion.choices[0].message.content?.trim() || "[]";
    // Strip markdown code fences if present
    content = content.replace(/^```(?:json)?\n?/, "").replace(/\n?```$/, "");
    const parsed = JSON.parse(content);
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    console.error("LLM analysis error:", err);
    return [];
  }
}

// ── Score & Risk Level ────────────────────────────────────────────────────────
function computeRisk(findings: Finding[]): {
  risk_score: number;
  risk_level: AuditResult["risk_level"];
} {
  const raw = findings.reduce((sum, f) => sum + (SEV_SCORE[f.severity] || 0), 0);
  const risk_score = Math.min(raw, 100);

  const hasCritical = findings.some(f => f.severity === "CRITICAL");
  const hasHigh     = findings.some(f => f.severity === "HIGH");
  const hasMedium   = findings.some(f => f.severity === "MEDIUM");
  const hasLow      = findings.some(f => f.severity === "LOW");

  let risk_level: AuditResult["risk_level"] = "SAFE";
  if (hasCritical)     risk_level = "CRITICAL";
  else if (hasHigh)    risk_level = "HIGH";
  else if (hasMedium)  risk_level = "MEDIUM";
  else if (hasLow)     risk_level = "LOW";

  return { risk_score, risk_level };
}

// ── Main Audit Function ───────────────────────────────────────────────────────
export async function auditContract(input: AuditInput): Promise<AuditResult> {
  const startMs = Date.now();
  const { contractAddress, sourceCode, quickMode = false } = input;

  // 1. Fetch bytecode from Pharos
  let bytecode = "";
  try {
    const raw = await pharosClient.getBytecode({
      address: contractAddress as `0x${string}`,
    });
    bytecode = raw || "";
  } catch (err) {
    console.warn("Could not fetch bytecode from Pharos:", err);
  }

  // 2. Bytecode heuristic analysis
  const bytecodeFindings = analyzeBytecode(bytecode);

  // 3. LLM semantic analysis (skip in quick mode or if no source)
  let llmFindings: Finding[] = [];
  if (!quickMode && sourceCode) {
    llmFindings = await analyzeLLM(contractAddress, sourceCode, bytecodeFindings);
  }

  // 4. Merge & deduplicate
  const allFindings: Finding[] = [...bytecodeFindings];
  const seenCategories = new Set(bytecodeFindings.map(f => f.category));
  for (const f of llmFindings) {
    if (!seenCategories.has(f.category)) {
      allFindings.push(f as Finding);
      seenCategories.add(f.category);
    }
  }

  // 5. Compute risk
  const { risk_score, risk_level } = computeRisk(allFindings);

  // 6. Count by severity
  const count = (sev: string) => allFindings.filter(f => f.severity === sev).length;

  // 7. Recommendation
  const safe_to_transact = !allFindings.some(f =>
    f.severity === "CRITICAL" || f.severity === "HIGH"
  );

  let recommendation = "Contract appears safe. Proceed with caution.";
  if (risk_level === "CRITICAL") {
    recommendation = "⛔ DO NOT TRANSACT. Critical vulnerabilities detected. Abort immediately.";
  } else if (risk_level === "HIGH") {
    recommendation = "⚠️  HIGH RISK. Transaction not recommended until issues are resolved.";
  } else if (risk_level === "MEDIUM") {
    recommendation = "🟡 Moderate risk. Review medium findings before proceeding.";
  } else if (risk_level === "LOW") {
    recommendation = "🟢 Low risk. Minor issues found. Safe to transact with awareness.";
  }

  return {
    contract_address: contractAddress,
    risk_score,
    risk_level,
    safe_to_transact,
    critical_count:   count("CRITICAL"),
    high_count:       count("HIGH"),
    medium_count:     count("MEDIUM"),
    low_count:        count("LOW"),
    findings:         allFindings,
    recommendation,
    audit_id:         `pharos-audit-${Date.now()}-${contractAddress.slice(2, 8)}`,
    duration_ms:      Date.now() - startMs,
  };
}
