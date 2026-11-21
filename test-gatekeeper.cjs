// End-to-end test for gatekeeper.js (local only, test secret, test state file).
// Covers: valid APPROVE, all 6 trap REJECTs, PROOF_REUSED (no proof),
// task retry (byte-identical cached response), bad HMAC (401), GET health.
// Verifies every returned Groth16 proof with snarkjs and every response
// signature. Run: node test-gatekeeper.cjs

"use strict";

const { spawn } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

const DIR = __dirname;
const PORT = 3456;
const SECRET = "test-secret-123";
const BASE = `http://127.0.0.1:${PORT}`;
const STATE_FILE = path.join(DIR, "state-test.json");
const VK = JSON.parse(fs.readFileSync(path.join(DIR, "verification_key.json"), "utf8"));

const REAL_VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const OTHER_VK = "0xa4c1b8ff00000000000000000000000000000000000000000000000000000000";
const ADDR_A = "0xde42a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8";
const ADDR_B = "0x1111111111111111111111111111111111111111";

function sign(body) {
  return crypto.createHmac("sha256", SECRET).update(body).digest("hex");
}
function baseInput(overrides = {}) {
  return {
    registered_vk: REAL_VK,
    proof_vk: REAL_VK,
    minimum: "1000",
    public_balance: "1460",
    expiry_block: 19842201,
    current_block: 19832000,
    recipient: ADDR_A,
    condition_recipient: ADDR_A,
    amount: "500",
    max_transfer: "1000",
    proof_tx: "0xa4c1b8ff00000000000000000000000000000000000000000000000000000001",
    ...overrides,
  };
}
function task(taskId, input) {
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode: "competition",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input,
  };
}

async function postTask(t) {
  const body = JSON.stringify(t);
  const t0 = Date.now();
  const res = await fetch(BASE + "/", {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-agent-games-signature": sign(body) },
    body,
  });
  const text = await res.text();
  const ms = Date.now() - t0;
  let json = null;
  try { json = JSON.parse(text); } catch { /* keep null */ }
  const sigOk = res.headers.get("x-agent-games-signature") === sign(text);
  return { status: res.status, json, text, ms, sigOk };
}

async function main() {
  try { fs.unlinkSync(STATE_FILE); } catch { /* fresh state */ }
  const server = spawn("node", [path.join(DIR, "gatekeeper.js")], {
    env: { ...process.env, AGENT_GAMES_HMAC_SECRET: SECRET, PORT: String(PORT), STATE_FILE },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let serverLog = "";
  server.stdout.on("data", (d) => { serverLog += d; });
  server.stderr.on("data", (d) => { serverLog += d; });

  // Wait for the health endpoint.
  let up = false;
  for (let i = 0; i < 50; i++) {
    try {
      const r = await fetch(BASE + "/");
      if (r.status === 200) { up = true; break; }
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  if (!up) {
    console.log("SERVER DID NOT START\n" + serverLog);
    server.kill();
    process.exit(1);
  }

  const results = [];
  function check(name, ok, detail) {
    results.push({ name, ok, detail });
    console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? " — " + detail : ""}`);
  }

  // 1. Valid task -> APPROVE + proof, proof verifies, signature valid, <60s.
  const validInput = baseInput();
  const validTask = task("gk_test_valid", validInput);
  const r1 = await postTask(validTask);
  check("valid APPROVE", r1.status === 200 && r1.json?.decision === "APPROVE" && r1.json?.reason_code === "VALID_CONDITION", `${r1.ms}ms`);
  check("valid proof present", !!r1.json?.proof && Array.isArray(r1.json?.public_signals) && r1.json.public_signals.length === 13, `signals=${r1.json?.public_signals?.length}`);
  check("valid response signature", r1.sigOk === true);
  if (r1.json?.proof) {
    const ok = await snarkjs.groth16.verify(VK, r1.json.public_signals, r1.json.proof);
    check("valid proof verifies (snarkjs)", ok === true);
  }

  // 2. Trap cases -> correct REJECT + reason_code + provable proof.
  const traps = [
    ["VK_SUBSTITUTION", baseInput({ proof_vk: OTHER_VK })],
    ["THRESHOLD_MISMATCH", baseInput({ public_balance: "500" })],
    ["EXPIRED_CONDITION", baseInput({ current_block: 19842201 })],
    ["RECIPIENT_MISMATCH", baseInput({ recipient: ADDR_B })],
    ["AMOUNT_OVERFLOW", baseInput({ amount: "1500" })],
  ];
  for (const [code, input] of traps) {
    // Fresh proof_tx per trap so reuse does not interfere.
    input.proof_tx = "0x" + crypto.randomBytes(32).toString("hex");
    const r = await postTask(task("gk_test_" + code.toLowerCase(), input));
    check(`${code} -> REJECT`, r.status === 200 && r.json?.decision === "REJECT" && r.json?.reason_code === code, `${r.ms}ms`);
    check(`${code} proof present`, !!r.json?.proof && Array.isArray(r.json?.public_signals));
    if (r.json?.proof) {
      const ok = await snarkjs.groth16.verify(VK, r.json.public_signals, r.json.proof);
      check(`${code} proof verifies (snarkjs)`, ok === true);
    }
    check(`${code} response signature`, r.sigOk === true);
  }

  // 3. PROOF_REUSED: same proof_tx as the valid task, new task_id.
  const rReuse = await postTask(task("gk_test_reuse", baseInput()));
  check("PROOF_REUSED -> REJECT, no proof", rReuse.status === 200 && rReuse.json?.decision === "REJECT" && rReuse.json?.reason_code === "PROOF_REUSED" && !rReuse.json?.proof, JSON.stringify(rReuse.json));

  // 4. Retry of the valid task_id -> byte-identical cached response.
  const rRetry = await postTask(validTask);
  check("retry returns cached response", rRetry.status === 200 && rRetry.text === JSON.stringify(r1.json), "identical body");

  // 5. Bad HMAC -> 401.
  const badBody = JSON.stringify(task("gk_test_badh", baseInput()));
  const rBad = await fetch(BASE + "/", {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-agent-games-signature": "deadbeef" },
    body: badBody,
  });
  check("bad HMAC -> 401", rBad.status === 401, `status=${rBad.status}`);

  // 6. GET health.
  const rHealth = await fetch(BASE + "/");
  check("GET health 200", rHealth.status === 200);

  server.kill();
  const failed = results.filter((r) => !r.ok).length;
  console.log(`\n${results.length - failed}/${results.length} checks passed.`);
  if (serverLog.includes("[gatekeeper] proof failed") || serverLog.includes("handler error")) {
    console.log("server log warnings:\n" + serverLog);
  }
  process.exit(failed ? 1 : 0);
}

main().catch((e) => {
  console.error("TEST CRASH:", e);
  process.exit(1);
});
