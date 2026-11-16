const assert = require("assert");
const { analyzeTransaction } = require("../src/analyzer");

async function runTests() {
  // 1. Safe native transfer
  const safe = await analyzeTransaction({
    chainId: 56,
    to: "0x10ED43C718714eb63d5aA57B78B54704E256024E",
    expectedRecipient: "0x10ED43C718714eb63d5aA57B78B54704E256024E",
    value: "100000000000000000",
    maxSafeValue: "1000000000000000000",
    data: "0x",
  });
  assert.strictEqual(safe.decision, "APPROVE");
  assert.strictEqual(safe.zk_proof.verified_locally, true);
  console.log("[PASS] Safe native transfer -> APPROVE, ZK proof verified");

  // 2. Unlimited ERC-20 approval trap
  const unlimited = await analyzeTransaction({
    chainId: 56,
    to: "0x55d398326f99059fF775485246999027B3197955",
    expectedRecipient: "0x55d398326f99059fF775485246999027B3197955",
    value: "0",
    maxSafeValue: "1000000000000000000",
    data: "0x095ea7b3000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeefffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  });
  assert.strictEqual(unlimited.decision, "REJECT");
  assert.ok(unlimited.flags.some((f) => f.code === "UNLIMITED_TOKEN_APPROVAL"));
  assert.strictEqual(unlimited.zk_proof.verified_locally, true);
  console.log("[PASS] Unlimited ERC-20 approval trap -> REJECT, ZK proof verified");

  // 3. NFT setApprovalForAll drain trap
  const nft = await analyzeTransaction({
    chainId: 1,
    to: "0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D",
    expectedRecipient: "0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D",
    value: "0",
    maxSafeValue: "1000000000000000000",
    data: "0xa22cb465000000000000000000000000badc0de0badc0de0badc0de0badc0de0badc0de00000000000000000000000000000000000000000000000000000000000000001",
  });
  assert.strictEqual(nft.decision, "REJECT");
  assert.ok(nft.flags.some((f) => f.code === "NFT_SET_APPROVAL_FOR_ALL"));
  assert.strictEqual(nft.zk_proof.verified_locally, true);
  console.log("[PASS] NFT setApprovalForAll drain -> REJECT, ZK proof verified");

  // 4. Value cap overflow
  const overflow = await analyzeTransaction({
    chainId: 56,
    to: "0x10ED43C718714eb63d5aA57B78B54704E256024E",
    expectedRecipient: "0x10ED43C718714eb63d5aA57B78B54704E256024E",
    value: "5000000000000000000",
    maxSafeValue: "1000000000000000000",
    data: "0x",
  });
  assert.strictEqual(overflow.decision, "REJECT");
  assert.ok(overflow.flags.some((f) => f.code === "VALUE_EXCEEDS_CAP"));
  assert.strictEqual(overflow.zk_proof.verified_locally, true);
  console.log("[PASS] Value cap overflow -> REJECT, ZK proof verified");

  console.log("\nALL WILDCARD TESTS PASSED!");
  process.exit(0);
}

runTests().catch((err) => {
  console.error(err);
  process.exit(1);
});
