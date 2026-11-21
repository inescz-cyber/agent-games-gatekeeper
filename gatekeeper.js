// Proof Gatekeeper endpoint for zkVerify Agent Games (Season 01).
// Agent: oxsyifa. Track: Proof Gatekeeper.
// Node.js, no framework. Receives a signed task envelope, verifies the HMAC
// on the raw body, decides deterministically (7 trap types), proves the
// decision with the tournament's own Groth16 circuit (snarkjs), and returns
// a signed JSON response — all within the 60-second window. Fail closed:
// any error, timeout or uncertainty means REJECT, never approve by default.
//
// Env:
//   AGENT_GAMES_HMAC_SECRET  per-agent secret from the dashboard (Rotate Secret)
//   PORT                     default 3000
//   STATE_FILE               default ./state.json (seen proof_tx + task cache)
//   CIRCUIT_DIR              default ./ (gatekeeper.wasm + gatekeeper_final.zkey)
//
// Run:  AGENT_GAMES_HMAC_SECRET=<secret> node gatekeeper.js
// Test: see test-gatekeeper.cjs (uses a test secret, no real secret needed).

"use strict";

const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// ---- config ---------------------------------------------------------------
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
const PORT = parseInt(process.env.PORT || "3000", 10);
const STATE_FILE = process.env.STATE_FILE || path.join(__dirname, "state.json");
const CIRCUIT_DIR = process.env.CIRCUIT_DIR || __dirname;
const WASM_PATH = path.join(CIRCUIT_DIR, "gatekeeper.wasm");
const ZKEY_PATH = path.join(CIRCUIT_DIR, "gatekeeper_final.zkey");

// BN254 scalar field order (snarkjs bn128). Field elements must be < FIELD_P.
const FIELD_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

if (!SECRET) {
  console.error("[gatekeeper] FATAL: AGENT_GAMES_HMAC_SECRET is not set. Refusing to start.");
  console.error("[gatekeeper] Copy the platform-generated secret from the dashboard (Rotate Secret).");
  process.exit(1);
}

// ---- state (seen proof_tx + task response cache), persisted to disk --------
let state = { seenProofTx: [], taskCache: {} };
try {
  if (fs.existsSync(STATE_FILE)) {
    state = JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
    state.seenProofTx = state.seenProofTx || [];
    state.taskCache = state.taskCache || {};
  }
} catch (e) {
  console.error("[gatekeeper] state file unreadable, starting empty:", e.message);
}
const seenProofTx = new Set(state.seenProofTx.map((s) => String(s).toLowerCase()));
function saveState() {
  state.seenProofTx = [...seenProofTx];
  const tmp = STATE_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(state));
  fs.renameSync(tmp, STATE_FILE);
}

// ---- helpers ---------------------------------------------------------------
function hmacHex(secret, rawBody) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}
function safeEqualHex(a, b) {
  try {
    const ba = Buffer.from(String(a), "utf8");
    const bb = Buffer.from(String(b), "utf8");
    return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
  } catch {
    return false;
  }
}
// Convert a hex (0x...) or decimal string to a BN254 field element (decimal string).
function toField(value) {
  let v;
  const s = String(value).trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) v = BigInt(s);
  else v = BigInt(s);
  return (v % FIELD_P).toString();
}
// Deterministic private salt per task (never sent; only a circuit input).
function taskSalt(taskId) {
  const h = crypto.createHash("sha256").update("agent-games-salt:" + taskId).digest("hex");
  return (BigInt("0x" + h) % FIELD_P).toString();
}
// Deterministic circuit taskId field element from the envelope's task_id string.
function taskIdField(taskId) {
  const h = crypto.createHash("sha256").update("agent-games-task:" + taskId).digest("hex");
  return (BigInt("0x" + h) % FIELD_P).toString();
}

// ---- decision logic --------------------------------------------------------
// Returns { decision: "APPROVE"|"REJECT", reason_code }.
// Check order follows the platform's trap encyclopedia listing.
function decide(input) {
  const registeredVk = String(input.registered_vk || "").toLowerCase();
  const proofVk = String(input.proof_vk || "").toLowerCase();
  const minimum = BigInt(String(input.minimum));
  const balance = BigInt(String(input.public_balance));
  const expiry = BigInt(String(input.expiry_block));
  const current = BigInt(String(input.current_block));
  const recipient = String(input.recipient || "").toLowerCase();
  const conditionRecipient = String(input.condition_recipient || "").toLowerCase();
  const amount = BigInt(String(input.amount));
  const maxTransfer = BigInt(String(input.max_transfer));
  const proofTx = String(input.proof_tx || "").toLowerCase();

  if (!proofVk || proofVk !== registeredVk) return { decision: "REJECT", reason_code: "VK_SUBSTITUTION" };
  if (balance < minimum) return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH" };
  if (proofTx && seenProofTx.has(proofTx)) return { decision: "REJECT", reason_code: "PROOF_REUSED" };
  if (current >= expiry) return { decision: "REJECT", reason_code: "EXPIRED_CONDITION" };
  if (!recipient || recipient !== conditionRecipient) return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH" };
  if (amount > maxTransfer) return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW" };
  return { decision: "APPROVE", reason_code: "VALID_CONDITION" };
}

// ---- proving ---------------------------------------------------------------
let snarkjs = null;
async function proveDecision(input, decision) {
  if (!snarkjs) snarkjs = require("snarkjs");
  const circuitInput = {
    registeredVkHash: toField(input.registered_vk),
    proofVkHash: toField(input.proof_vk),
    minimum: String(input.minimum),
    publicBalance: String(input.public_balance),
    expiryBlock: String(input.expiry_block),
    currentBlock: String(input.current_block),
    recipient: toField(input.recipient),
    conditionRecipient: toField(input.condition_recipient),
    amount: String(input.amount),
    maxTransfer: String(input.max_transfer),
    decision: decision === "APPROVE" ? "1" : "0",
    taskId: taskIdField(input.task_id),
    salt: taskSalt(input.task_id),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput, WASM_PATH, ZKEY_PATH
  );
  return { proof, publicSignals };
}

// ---- request handling ------------------------------------------------------
function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  const sig = hmacHex(SECRET, body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "x-agent-games-signature": sig,
  });
  res.end(body);
  return { body, sig };
}

async function handleTask(task) {
  const input = task.input || {};
  const taskId = String(task.task_id || "");
  const proofTx = String(input.proof_tx || "").toLowerCase();
  if (!taskId || !input.registered_vk || !input.proof_vk || !proofTx) {
    return { status: 400, response: { decision: "REJECT", reason_code: "INVALID", proof_tx: proofTx || "" } };
  }

  // Idempotency: a retried task returns the byte-identical cached response.
  if (state.taskCache[taskId]) {
    return { status: 200, cached: state.taskCache[taskId] };
  }

  const { decision, reason_code } = decide(input);
  let response = { decision, reason_code, proof_tx: proofTx };

  if (reason_code !== "PROOF_REUSED") {
    // The circuit is the referee: a wrong decision cannot produce a proof.
    try {
      const { proof, publicSignals } = await proveDecision(input, decision);
      response.proof = proof;
      response.public_signals = publicSignals;
    } catch (e) {
      // Proof failed for the computed decision. If we computed APPROVE, the
      // circuit says the task is not valid: fall back to REJECT (fail closed)
      // and try to prove the rejection instead. Never flip REJECT -> APPROVE.
      console.error(`[gatekeeper] proof failed for ${taskId} (${decision}/${reason_code}): ${e.message}`);
      if (decision === "APPROVE") {
        // Circuit refused the approval: the task is not valid. Fall back to
        // REJECT (fail closed) and try to prove the rejection instead.
        response = { decision: "REJECT", reason_code: "INVALID", proof_tx: proofTx };
        try {
          const { proof, publicSignals } = await proveDecision(input, "REJECT");
          response.proof = proof;
          response.public_signals = publicSignals;
        } catch {
          // Still failing: return the REJECT with no proof (fail closed).
        }
      }
      // decision was REJECT and its proof failed: conversion bug, not a trap.
      // Keep the REJECT (fail closed) with no proof.
    }
  }

  // Record the proof reference as seen, and cache the response for retries.
  if (proofTx) seenProofTx.add(proofTx);
  state.taskCache[taskId] = response;
  saveState();
  return { status: 200, response };
}

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", async () => {
    const rawBody = Buffer.concat(chunks);
    try {
      // Health check (no signature needed for GET).
      if (req.method === "GET") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ status: "ok", agent: "oxsyifa", track: "proof-gatekeeper" }));
        return;
      }
      if (req.method !== "POST") {
        res.writeHead(405);
        res.end();
        return;
      }
      // Verify the HMAC signature against the raw body BEFORE parsing.
      const sig = req.headers["x-agent-games-signature"] || req.headers["x-signature"] || "";
      if (!sig || !safeEqualHex(sig, hmacHex(SECRET, rawBody))) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "invalid signature" }));
        return;
      }
      let task;
      try {
        task = JSON.parse(rawBody.toString("utf8"));
      } catch {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "invalid json" }));
        return;
      }
      // Preflight / health POSTs: a signed body that is not a task envelope.
      if (!task || task.type !== "agent-games.proof-gatekeeper.v1") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ status: "ok", agent: "oxsyifa" }));
        return;
      }
      // 50s safety guard: the platform's hard deadline is 60s.
      const timeout = setTimeout(() => {
        if (!res.writableEnded) {
          sendJson(res, 200, { decision: "REJECT", reason_code: "INVALID", proof_tx: String((task.input || {}).proof_tx || "") });
        }
      }, 50000);
      const result = await handleTask(task);
      clearTimeout(timeout);
      if (res.writableEnded) return;
      if (result.cached) {
        const body = JSON.stringify(result.cached);
        const sigOut = hmacHex(SECRET, body);
        res.writeHead(200, { "Content-Type": "application/json", "x-agent-games-signature": sigOut });
        res.end(body);
        return;
      }
      sendJson(res, result.status, result.response);
    } catch (e) {
      console.error("[gatekeeper] handler error:", e);
      if (!res.writableEnded) {
        try {
          sendJson(res, 200, { decision: "REJECT", reason_code: "INVALID", proof_tx: "" });
        } catch { res.writeHead(500); res.end(); }
      }
    }
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`[gatekeeper] oxsyifa listening on 0.0.0.0:${PORT} (circuit: ${WASM_PATH})`);
});
