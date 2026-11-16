# zkGuard — Verifiable EVM/BSC Wallet & Transaction Security Agent (Wildcard)

An autonomous Web3 wallet security guard built for the **zkVerify Agent Games — Wildcard** track.

## Problem
Crypto users and autonomous agents regularly lose funds to blind-signing wallet drainers: unlimited ERC-20 `approve(...)`, malicious `setApprovalForAll(true)` NFT approvals, off-chain EIP-2612 `permit` signatures, recipient spoofing, and value-cap overflows.

## Solution
**zkGuard** deterministically decodes and screens every EVM/BSC transaction **before signing**, assigns a risk score (`0–100`) with human-readable security flags, and generates a **Groth16 zero-knowledge proof** (using the zkVerify-registered gatekeeper circuit `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`) attesting that the transaction satisfied or violated the configured safety policy.

## Endpoints
- `GET /` — Interactive web dashboard with 1-click trap presets & live ZK proof generation
- `POST /analyze` (and `POST /agent`) — JSON API for transaction screening + Groth16 proof output
- `GET /health` — Service health check

## Quick Start
```bash
npm install
npm test
npm start
```
