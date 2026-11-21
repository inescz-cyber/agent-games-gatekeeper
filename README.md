# agent-games-gatekeeper

Proof Gatekeeper agent for zkVerify Agent Games (Season 01).

- **Agent:** oxsyifa
- **Track:** Proof Gatekeeper — approve or reject proof-backed payment requests.

## How it works

`gatekeeper.js` is a dependency-free Node.js HTTP endpoint. For each task it:

1. Verifies the HMAC-SHA256 signature on the raw request body, using the
   per-agent secret from the Agent Games dashboard (Rotate Secret).
2. Decides deterministically (7 trap types) whether the payment request is
   valid.
3. Proves the decision with the tournament's own Groth16 circuit (snarkjs)
   and returns a signed JSON response — all within the 60-second window.
4. Fails closed: any error, timeout, or uncertainty means REJECT, never
   approve by default.

## Run

```sh
AGENT_GAMES_HMAC_SECRET=<secret from the dashboard> node gatekeeper.js
```

Environment variables:

- `AGENT_GAMES_HMAC_SECRET` — required. Per-agent secret from the dashboard.
- `PORT` — default `3000`.
- `STATE_FILE` — default `./state.json` (seen proof_tx + task cache).
- `CIRCUIT_DIR` — default `./` (expects `gatekeeper.wasm` +
  `gatekeeper_final.zkey` there).

## Test

```sh
node test-gatekeeper.cjs
```

The test suite uses a test secret only; no real secret is needed. It covers
28 cases locally (valid, trap, and verification-key-mismatch inputs).

## Notes

- `gatekeeper.wasm` and `gatekeeper_final.zkey` are compiled circuit
  artifacts. They are not in this repository; place them in the repo root
  (or set `CIRCUIT_DIR`) to run the prover.
- `verification_key.json` is the Groth16 verification key for the circuit.
- `input-*.json` / `proof*.json` / `public*.json` are test vectors and
  sample proofs. `leaderboard.json` is a local snapshot, not live data.
