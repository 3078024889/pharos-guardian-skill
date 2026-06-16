/**
 * GuardianSkill Integration Test
 * Tests the full skill pipeline without needing real x402 payments.
 */

import { auditContract } from "../server/guardian_core.js";

const TEST_CASES = [
  {
    name:    "Empty address (no bytecode)",
    address: "0x0000000000000000000000000000000000000000",
    expect:  { risk_level: "CRITICAL" },
  },
  {
    name:    "Contract with source code — reentrancy vulnerability",
    address: "0x1111111111111111111111111111111111111111",
    source_code: `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// INTENTIONALLY VULNERABLE — for testing only
contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // BUG: classic reentrancy — sends ETH before updating balance
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount; // should be BEFORE the call
    }

    // BUG: no access control — anyone can drain
    function emergencyDrain() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}`,
    expect: { safe_to_transact: false },
  },
];

async function runTests() {
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("  🧪 GuardianSkill Integration Tests");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

  let passed = 0;
  let failed = 0;

  for (const tc of TEST_CASES) {
    console.log(`📋 Test: ${tc.name}`);
    try {
      const result = await auditContract({
        contractAddress: tc.address,
        sourceCode:      tc.source_code,
        chain:           "pharos",
      });

      console.log(`   Risk Level:  ${result.risk_level}`);
      console.log(`   Risk Score:  ${result.risk_score}/100`);
      console.log(`   Safe:        ${result.safe_to_transact}`);
      console.log(`   Findings:    ${result.findings.length}`);
      console.log(`   Duration:    ${result.duration_ms}ms`);

      // Check expectation
      let ok = true;
      if (tc.expect.risk_level && result.risk_level !== tc.expect.risk_level) {
        console.log(`   ❌ Expected risk_level=${tc.expect.risk_level}, got ${result.risk_level}`);
        ok = false;
      }
      if (tc.expect.safe_to_transact !== undefined &&
          result.safe_to_transact !== tc.expect.safe_to_transact) {
        console.log(`   ❌ Expected safe_to_transact=${tc.expect.safe_to_transact}`);
        ok = false;
      }

      if (ok) {
        console.log("   ✅ PASSED\n");
        passed++;
      } else {
        failed++;
        console.log();
      }

    } catch (err: any) {
      console.log(`   ❌ ERROR: ${err.message}\n`);
      failed++;
    }
  }

  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log(`Results: ${passed} passed, ${failed} failed`);
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  process.exit(failed > 0 ? 1 : 0);
}

runTests();
