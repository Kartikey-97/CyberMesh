# CyberMesh — Zero-Trust Access Control for Decentralized APIs

## Problem Statement
**BACKGROUND:**
Enterprise applications run across highly distributed multi-cloud architectures. Traditional perimeter firewalls cannot easily police lateral internal API communication.

**THE PAIN POINT:**
Once an attacker breaks into one vulnerable edge micro service, they move laterally across internal networks unhindered, scraping backend databases via unsecured APIs.

**CORE REQUIREMENTS:**
Construct a light dynamic service mesh proxy that enforces cryptographic identity for every single microservice request. Implement contextual policies (time, geo, payload anomalies) that actively re-authenticate endpoints dynamically.

**EVALUATION METRIC:**
Proxy overhead latency (<= 15ms), detection rate of lateral movement anomalies, and robustness of dynamic token cryptographic validation.

---

## 1. The Problem (What We’re Actually Solving)
Modern enterprise apps run as many small microservices talking to each other internally (user-service, billing-service, admin-service, etc.), often across multiple clouds. Traditional security = a firewall around the whole network. Once you’re “inside,” every service implicitly trusts every other service.

**The failure mode:** if an attacker compromises just ONE low-value, internet-facing microservice, they can move sideways (“lateral movement”) to any other internal service — including sensitive ones like an admin or database service — because nothing checks identity or intent between internal calls today.

This is NOT a vulnerability scanner. We are not scanning code for bugs or patching CVEs. We are building an enforcement layer that sits between every microservice and verifies, on every single request, “are you really who you say you are, and are you actually allowed to call this specific target right now?”

## 2. What We’re Building
**CyberMesh:** a lightweight zero-trust proxy (“mini service mesh”) that:
1. Gives every microservice a cryptographic identity (signed JWT, upgradeable to mTLS)
2. Forces ALL inter-service traffic through a central enforcement point (the proxy)
3. Checks identity + an allowlist policy + contextual rules (rate, time, payload shape) on every request, every time — no persistent trust, no one-time login
4. Auto-generates its own policy by watching real traffic for ~30s (“learning mode”), instead of requiring hand-written config — this is our signature differentiator
5. Scores every request with a Trust Score instead of a binary allow/block — combining identity confidence, behavioral history, and context into one number, with a middle band that triggers re-authentication instead of an outright block
6. Explains every block with a Risk Explanation Engine — a checklist of every reason that fired (new/unseen target, trust score below threshold, rate limit exceeded, not in learned policy), not just a single opaque “blocked”
7. Can revoke a service’s access instantly, mid-session, from a live dashboard
8. Shows everything happening in real time on a dashboard: allowed/blocked requests, the learned policy as a live graph, a threat timeline, latency, and the full reason breakdown for every block

**The demo narrative:** normal traffic flows and gets auto-learned into a policy graph → we flip to enforce mode → an “attacker” (compromised billing-service) tries to call admin-service, which it was never observed calling → instantly blocked, with a live threat timeline and a full reason breakdown shown on screen → bonus: we revoke a service’s identity mid-flight from the dashboard and its next request dies immediately.

## 3. Why This Beats “Just Use Istio” (Our Positioning)
We are NOT claiming to be technically superior to Istio. Istio is mature, powerful, industry-standard. Our pitch is about who Istio underserves:
- Istio requires Kubernetes, a control plane, sidecar injection, and real platform engineering expertise — weeks of setup, ongoing operational burden.
- Istio’s policy config (AuthorizationPolicy, PeerAuthentication, DestinationRule, etc.) is verbose and requires expertise just to express one rule.
- It’s all-or-nothing — no incremental adoption path.

**Our line:** “Istio is right for large, Kubernetes-native orgs with a dedicated platform team. We’re for the other 90% — teams who need zero-trust enforcement now, without hiring a platform team or rewriting their infra.”

**Concrete differentiators:**
- Deploys in minutes, not weeks
- No Kubernetes requirement — works on Docker, VMs, mixed environments
- Incremental adoption — protect your 2-3 riskiest services first
- Auto-generated policy from observed traffic — no YAML/DSL expertise needed
- Plain-language dashboard explanations, not opaque telemetry

## 4. System Architecture
```text
 ┌─────────────────┐
 │ auth-service    │ (mini-CA)
 │ issues signed   │
 │ identity tokens │
 └────────┬────────┘
          │ (tokens issued at startup)
          │
 user-service ──┐ │                      ┌──► admin-service
                │ │                      │
 billing-service ─┼──► [ CYBERMESH PROXY ] ────────┼──► (actual forwarding
                │ - verify identity      │      if allowed)
 admin-service ──┘ - check policy         │
                  - check context rules  │
                  - trust score engine   │
                  - risk explanation engine │
                  - learning mode logger │
                  - event stream (→ dashboard) │
                  │
                  ▼
                ┌─────────────────┐
                │ Dashboard       │ live allow/block feed,
                │ (Person 3)      │ policy graph, threat
                │                 │ timeline, trust scores,
                │                 │ reason breakdowns, revoke
                └─────────────────┘
```
No microservice ever calls another microservice directly. All routing goes through the proxy, which is the single enforcement point (functionally a centralized “sidecar”).

## 5. Core Components & How They Work
### 5.1 Auth-service (mini-CA)
- Holds a signing secret (or private key, if using mTLS/RS256)
- On startup, each microservice authenticates with a pre-shared key and receives a short-lived signed JWT: `{"sub": "billing-service", "exp": <60s from now>}`
- Exposes a `/revoke` endpoint — the kill-switch. Marks a service’s identity invalid immediately; the next request it makes fails even with a technically unexpired token.

### 5.2 Mock microservices
- 3 dumb FastAPI apps: user-service, billing-service, admin-service
- Each has 1-2 trivial endpoints (fake data) — they exist purely to demonstrate lateral movement between them
- None are directly reachable — only through the proxy

### 5.3 The Proxy (core enforcement + policy engine)
- Receives every inter-service request
- Verifies the JWT signature and expiry
- Learning mode: logs every (caller → target) pair it observes; after the observation window, generates a simple human-readable allowlist automatically (e.g. `billing-service → user-service: allow`)
- Enforce mode: checks caller/target against the learned (or fallback) policy
- Contextual checks: rate limiting, time-of-day window, payload shape/anomaly detection
- Pushes every decision (allow/block + full reason breakdown) to a live event stream for the dashboard
- Exposes the same `/revoke` hook so the dashboard’s kill-switch button works live

### 5.4 Trust Score Engine
Instead of a single pass/fail check, every request gets scored across three inputs:
`trust_score = (identity_score * 0.4) + (behavior_score * 0.3) + (context_score * 0.3)`

Decision bands:
- **Trust > 80 → Allow**
- **Trust 50-80 → Step-up re-authentication** (request a fresh short-lived token before forwarding)
- **Trust < 50 → Block**

### 5.5 Risk Explanation Engine
Every block (or step-up challenge) surfaces the full list of reasons that fired.

### 5.6 Attack simulation script
- Plays normal traffic during learning mode (so a real policy gets learned)
- Then, in enforce mode: attempts unauthorized lateral movement, rate-limit abuse, and a malformed payload.

### 5.7 Fallback path (backup for the live-learning demo)
- A pre-recorded traffic log (JSON fixture) that can be replayed instantly.

### 5.8 Dashboard
- Consumes the proxy’s live event stream (WebSocket/SSE)
- Shows: request flow in real time, a running latency counter, and a manual revoke/kill-switch button per service
- Policy graph view
- Threat timeline
- Reason breakdown panel

## 6. Feature List (Priority Order — Build in This Order)
1. **[MUST]** Auth-service issuing JWTs + basic proxy with a hardcoded policy, all 3 services routable through it
2. **[MUST]** Attack script proving block/allow works against the hardcoded policy
3. **[MUST]** Dashboard wired to the real event stream
4. **[CORE DIFFERENTIATOR]** Learning mode — auto-generates the policy from observed traffic
5. **[HIGH VALUE, LOW COST]** Trust Score Engine — weighted scoring on top of checks you’re already computing
6. **[HIGH VALUE, LOW COST]** Risk Explanation Engine — log every check’s result
7. **[MUST — SAFETY NET]** Fallback replay path for the learning-mode demo
8. **[BONUS]** In-flight revocation / live kill-switch
9. **[POLISH]** Dashboard upgrades
10. **[STRETCH]** mTLS instead of JWT-only identity
11. **[STRETCH]** Per-service distributed sidecars instead of one central proxy
