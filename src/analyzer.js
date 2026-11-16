const crypto = require("crypto");
const path = require("path");
const snarkjs = require("snarkjs");
const { keccak256, toBytes } = require("viem");

const SNARK_SCALAR_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const WASM_PATH = path.join(__dirname, "..", "circuits", "gatekeeper.wasm");
const ZKEY_PATH = path.join(__dirname, "..", "circuits", "gatekeeper_final.zkey");
const ZKVERIFY_VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

const UNLIMITED_THRESHOLD = 1n << 255n;

// Known legitimate routers (lowercased) for context-aware risk scoring
const KNOWN_SAFE_ROUTERS = new Set([
  "0x10ed43c718714eb63d5aa57b78b54704e256024e", // PancakeSwap v2 Router (BSC)
  "0x13f4ea83d0bd40e75c8222255bc855a974568dd4", // PancakeSwap Smart Router (BSC)
  "0x7a250d5630b4cf539739df2c5dacb4c659f2488d", // Uniswap v2 Router (ETH)
  "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45", // Uniswap SwapRouter02
]);

const SELECTORS = {
  "0x095ea7b3": "approve(address,uint256)",
  "0xa22cb465": "setApprovalForAll(address,bool)",
  "0xd505accf": "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
  "0x39509351": "increaseAllowance(address,uint256)",
  "0xa9059cbb": "transfer(address,uint256)",
  "0x23b872dd": "transferFrom(address,address,uint256)",
  "0xac9650d8": "multicall(bytes[])",
};

let vkCache = null;
async function getVk() {
  if (!vkCache) vkCache = await snarkjs.zKey.exportVerificationKey(ZKEY_PATH);
  return vkCache;
}

function toFieldElement(val) {
  if (typeof val === "number" || typeof val === "bigint") {
    return (BigInt(val) % SNARK_SCALAR_FIELD).toString();
  }
  const s = String(val).trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return (BigInt(s) % SNARK_SCALAR_FIELD).toString();
  if (/^\d+$/.test(s)) return (BigInt(s) % SNARK_SCALAR_FIELD).toString();
  return (BigInt(keccak256(toBytes(s))) % SNARK_SCALAR_FIELD).toString();
}

function readAddressWord(hexBody, wordIndex) {
  const start = wordIndex * 64;
  if (hexBody.length < start + 64) return null;
  return "0x" + hexBody.slice(start + 24, start + 64).toLowerCase();
}

function readUint256Word(hexBody, wordIndex) {
  const start = wordIndex * 64;
  if (hexBody.length < start + 64) return null;
  return BigInt("0x" + hexBody.slice(start, start + 64));
}

function decodeCalldata(data) {
  const hex = String(data || "0x").trim().toLowerCase();
  if (!hex || hex === "0x" || hex.length < 10) {
    return { selector: "0x", signature: "native_transfer", args: {} };
  }
  const selector = hex.slice(0, 10);
  const body = hex.slice(10);
  const signature = SELECTORS[selector] || "unknown_function";

  if (selector === "0x095ea7b3" || selector === "0x39509351" || selector === "0xa9059cbb") {
    return {
      selector,
      signature,
      args: {
        target: readAddressWord(body, 0),
        amount: readUint256Word(body, 1)?.toString() ?? "0",
      },
    };
  }
  if (selector === "0xa22cb465") {
    const approved = (readUint256Word(body, 1) ?? 0n) !== 0n;
    return {
      selector,
      signature,
      args: {
        operator: readAddressWord(body, 0),
        approved,
      },
    };
  }
  if (selector === "0xd505accf") {
    return {
      selector,
      signature,
      args: {
        owner: readAddressWord(body, 0),
        spender: readAddressWord(body, 1),
        value: readUint256Word(body, 2)?.toString() ?? "0",
        deadline: readUint256Word(body, 3)?.toString() ?? "0",
      },
    };
  }
  if (selector === "0x23b872dd") {
    return {
      selector,
      signature,
      args: {
        from: readAddressWord(body, 0),
        to: readAddressWord(body, 1),
        amount: readUint256Word(body, 2)?.toString() ?? "0",
      },
    };
  }
  return { selector, signature, args: {} };
}

/**
 * Screen an EVM/BSC transaction against deterministic wallet-safety rules
 * and generate a Groth16 ZK proof attesting to the policy evaluation.
 */
async function analyzeTransaction(tx) {
  const to = String(tx.to || "0x0000000000000000000000000000000000000000").trim().toLowerCase();
  const expectedRecipient = String(tx.expectedRecipient || to).trim().toLowerCase();
  const value = BigInt(tx.value ?? 0);
  const maxValue = BigInt(tx.maxSafeValue ?? "1000000000000000000"); // default 1 ETH/BNB
  const chainId = Number(tx.chainId ?? 56);
  const currentBlock = BigInt(tx.currentBlock ?? 42000000);
  const expiryBlock = BigInt(tx.expiryBlock ?? currentBlock + 100n);
  const decoded = decodeCalldata(tx.data);

  const flags = [];
  let riskScore = 0;

  // 1. Recipient mismatch check
  if (to !== expectedRecipient) {
    flags.push({
      code: "RECIPIENT_MISMATCH",
      severity: "HIGH",
      detail: `Transaction target ${to} does not match expected recipient ${expectedRecipient}.`,
    });
    riskScore += 70;
  }

  // 2. Native value cap check
  if (value > maxValue) {
    flags.push({
      code: "VALUE_EXCEEDS_CAP",
      severity: "HIGH",
      detail: `Native value ${value} wei exceeds policy cap ${maxValue} wei.`,
    });
    riskScore += 65;
  }

  // 3. Expired block window check
  if (currentBlock >= expiryBlock) {
    flags.push({
      code: "EXPIRED_WINDOW",
      severity: "MEDIUM",
      detail: `Current block ${currentBlock} has reached/passed expiry block ${expiryBlock}.`,
    });
    riskScore += 45;
  }

  // 4. Calldata drain/approval traps
  if (decoded.selector === "0x095ea7b3" || decoded.selector === "0x39509351") {
    const amt = BigInt(decoded.args.amount || 0);
    const spender = decoded.args.target || "";
    const isKnownRouter = KNOWN_SAFE_ROUTERS.has(spender);
    if (amt >= UNLIMITED_THRESHOLD) {
      flags.push({
        code: "UNLIMITED_TOKEN_APPROVAL",
        severity: isKnownRouter ? "MEDIUM" : "CRITICAL",
        detail: isKnownRouter
          ? `Unlimited approval to known router ${spender}. Prefer exact-amount approvals.`
          : `Unlimited ERC-20 approval to unverified spender ${spender} — classic wallet-drain vector.`,
      });
      riskScore += isKnownRouter ? 40 : 95;
    } else if (!isKnownRouter) {
      flags.push({
        code: "UNKNOWN_SPENDER_APPROVAL",
        severity: "MEDIUM",
        detail: `Token approval to unverified spender ${spender}.`,
      });
      riskScore += 35;
    }
  } else if (decoded.selector === "0xa22cb465" && decoded.args.approved) {
    const operator = decoded.args.operator || "";
    const isKnownRouter = KNOWN_SAFE_ROUTERS.has(operator);
    flags.push({
      code: "NFT_SET_APPROVAL_FOR_ALL",
      severity: isKnownRouter ? "MEDIUM" : "CRITICAL",
      detail: `setApprovalForAll(true) grants full NFT collection transfer rights to ${operator}.`,
    });
    riskScore += isKnownRouter ? 40 : 95;
  } else if (decoded.selector === "0xd505accf") {
    const amt = BigInt(decoded.args.value || 0);
    flags.push({
      code: "OFFCHAIN_PERMIT_SIGNATURE",
      severity: amt >= UNLIMITED_THRESHOLD ? "CRITICAL" : "HIGH",
      detail: `EIP-2612 permit grants allowance (${amt >= UNLIMITED_THRESHOLD ? "UNLIMITED" : amt}) via off-chain signature to ${decoded.args.spender}.`,
    });
    riskScore += amt >= UNLIMITED_THRESHOLD ? 90 : 55;
  } else if (decoded.selector === "0xac9650d8") {
    flags.push({
      code: "MULTICALL_BATCH",
      severity: "MEDIUM",
      detail: "Multicall batch detected — inspect inner calls before signing.",
    });
    riskScore += 35;
  }

  riskScore = Math.min(100, riskScore);
  const decision = riskScore >= 40 ? "REJECT" : "APPROVE";
  const riskLevel = riskScore >= 70 ? "CRITICAL" : riskScore >= 40 ? "HIGH" : "LOW";

  // Map deterministic risk-threshold check onto the zkVerify-registered Groth16 circuit
  // (riskScore <= 39 => APPROVE (1), riskScore >= 40 => REJECT (0)).
  const taskId = "zkguard_" + crypto.randomUUID();
  const salt = (BigInt("0x" + crypto.randomBytes(16).toString("hex")) % SNARK_SCALAR_FIELD).toString();

  const circuitInput = {
    registeredVkHash: toFieldElement(ZKVERIFY_VK_HASH),
    proofVkHash: toFieldElement(ZKVERIFY_VK_HASH),
    minimum: "0",
    publicBalance: "100",
    expiryBlock: toFieldElement(expiryBlock),
    currentBlock: toFieldElement(currentBlock),
    recipient: toFieldElement(to),
    conditionRecipient: toFieldElement(expectedRecipient),
    amount: String(riskScore),
    maxTransfer: "39",
    decision: decision === "APPROVE" ? "1" : "0",
    taskId: toFieldElement(taskId),
    salt,
  };

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput,
    WASM_PATH,
    ZKEY_PATH
  );
  const vk = await getVk();
  const verifiedLocally = await snarkjs.groth16.verify(vk, publicSignals, proof);

  return {
    task_id: taskId,
    chain_id: chainId,
    decision,
    risk_score: riskScore,
    risk_level: riskLevel,
    flags,
    decoded,
    zk_proof: {
      protocol: "groth16",
      curve: "bn128",
      zkverify_vk_hash: ZKVERIFY_VK_HASH,
      verified_locally: verifiedLocally,
      public_signals: publicSignals,
      proof,
    },
  };
}

module.exports = { analyzeTransaction, decodeCalldata, ZKVERIFY_VK_HASH };
