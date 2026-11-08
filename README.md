<!--
  © 2026 Satyendra Singh. All Rights Reserved.
  Author: Satyendra Singh
-->

# SentinelGuard

**Reactive Distributed Rate-Limiter and Fraud Detection Engine**

© 2026 Satyendra Singh. All Rights Reserved. · Author: **Satyendra Singh**

Java 21 · Spring Boot 3.4 · Spring WebFlux · Reactive Redis (Lettuce) · Apache Kafka

---

## 1. What this service is

SentinelGuard is an edge service that fuses two concerns normally bolted on
separately, and does both without ever blocking an event-loop thread:

| Concern | Mechanism |
|---|---|
| **Distributed rate limiting** | Redis-backed token bucket whose entire read–modify–write cycle executes inside one atomic Lua script |
| **Fraud detection** | Behavioural heuristics scored over atomic Redis sliding windows, with alerts streamed asynchronously to the `fraud-alerts` Kafka topic |

There is no `block()` anywhere in the production source set, no distributed
lock, and no optimistic-retry loop.

---

## 2. Request flow

```
                    ┌──────────────────────────────────────────────┐
  HTTP request ───► │ CorrelationIdWebFilter        (order -200)   │
                    │   mints / honours X-Correlation-Id           │
                    └───────────────────┬──────────────────────────┘
                                        ▼
                    ┌──────────────────────────────────────────────┐
                    │ RateLimitWebFilter            (order -150)   │
                    │  1. excluded path?  ──► pass through         │
                    │  2. fingerprint + resolve policy             │
                    │  3. EVALSHA token_bucket.lua  ──► Redis      │
                    └───────┬──────────────────────────┬───────────┘
              allowed ◄─────┘                          └─────► denied
                    │                                            │
                    ▼                                            ▼
          handler + X-RateLimit-*                    429 + Retry-After
                    │                                            │
                    └────────────► FraudDetectionEngine ◄─────────┘
                                   (detached subscription)
                                            │
                              EVALSHA sliding_window.lua ──► Redis
                                            │
                                   score ≥ threshold?
                                            │
                                            ▼
                              KafkaTemplate ──► topic: fraud-alerts
```

The fraud evaluation is fired on a **detached subscription**: scoring performs
Redis and Kafka I/O, and a customer must never wait for telemetry.

---

## 3. Why a Lua script, and not `GET` / compute / `SET`

The naive distributed limiter reads the bucket, computes the refill, then writes
it back. With *N* replicas that sequence interleaves:

```
replica A: GET tokens -> 1          replica B: GET tokens -> 1
replica A: SET tokens = 0           replica B: SET tokens = 0
           ▲ both requests admitted, one token spent twice
```

That lost update is exactly how a "rate limited" service still gets flattened by
a burst. Redis evaluates a Lua script as a single indivisible unit on its command
thread, so `token_bucket.lua` serialises the cycle **globally** in one round
trip, with:

* **lazy refill** — tokens are credited only for whole elapsed intervals, and the
  watermark advances in exact interval multiples so no fractional token leaks at
  high request rates;
* **a precise retry hint** — the script returns the exact millisecond deficit, so
  `Retry-After` is computed, never guessed;
* **self-pruning keys** — `PEXPIRE` is refreshed in the same atomic unit, so a
  dormant caller's bucket evicts itself;
* **cluster safety** — exactly one key per invocation, hence always single-slot;
* **fail-loud validation** — a misconfigured policy returns a Redis error rather
  than silently degrading into an unlimited bucket.

Scripts are dispatched with `EVALSHA` (Spring Data Redis loads them once and
falls back to `EVAL` on a `NOSCRIPT` reply), so only a 40-byte digest crosses the
wire per request.

---

## 4. Fraud scoring model

| Signal | Weight | Fires when |
|---|---|---|
| `RATE_LIMIT_BREACH` | 25 | the request was just rejected by the bucket |
| `BURST_VELOCITY` | 30 | rejections in the window ≥ `burst-rejection-threshold` |
| `PATH_ENUMERATION` | 25 | distinct paths in the window > `distinct-path-threshold` |
| `SUSPICIOUS_USER_AGENT` | 20 | the agent matches a configured automation signature |
| `MISSING_USER_AGENT` | 15 | no `User-Agent` at all |
| `ANONYMOUS_IDENTITY` | 10 | no verifiable credential was presented |

Weights are additive and mapped to a band: `LOW ≥ 1`, `MEDIUM ≥ 30`,
`HIGH ≥ 55`, `CRITICAL ≥ 80`. The default publication floor is `MEDIUM`, and the
weights are tuned so **no single weak indicator can reach it alone** while any
two correlated indicators can — which is what keeps the topic signal-dense
instead of full of "anonymous caller with no User-Agent".

Alerts are keyed by client identity, so one caller's alerts land on one
partition and reach consumers in causal order — enough for a downstream
processor to run a per-identity state machine ("three MEDIUM alerts in a minute
⇒ auto-block") with no repartition step.

---

## 5. Layout

```
sentinelguard/
├── pom.xml                         Spring Boot 3.4, Java 21, JaCoCo branch gate
├── Dockerfile                      multi-stage, layered, non-root, healthchecked
├── docker-compose.yml              app + Redis + Kafka (KRaft) + optional Kafka UI
└── src
    ├── main
    │   ├── java/com/satyendra/sentinelguard
    │   │   ├── SentinelGuardApplication.java
    │   │   ├── config/             properties, Redis scripts, Kafka producer, Clock
    │   │   ├── domain/             immutable records + enums (the whole model)
    │   │   ├── limiter/            RateLimiter, Redis token bucket, policy resolver
    │   │   ├── fraud/              sliding window, detection engine, Kafka publisher
    │   │   └── web/                filters, controllers, error contract, DTOs
    │   └── resources
    │       ├── application.yml
    │       └── scripts/
    │           ├── token_bucket.lua
    │           └── sliding_window.lua
    └── test/java/com/satyendra/sentinelguard
        ├── limiter/ fraud/ web/    JUnit 5 + Mockito + StepVerifier unit tests
        └── integration/
            └── SentinelGuardEndToEndIT.java   live Redis + Kafka via Testcontainers
```

---

## 6. Run it

### Whole stack (nothing else required)

```bash
docker compose up --build
# optional: topic browser on http://localhost:8081
docker compose --profile tools up -d kafka-ui
```

Kafka is published on host port **29092** (not 9092) so the stack does not
collide with whatever other local Kafka is already running; override with
`KAFKA_HOST_PORT=9092 docker compose up`. Containers always talk to `kafka:19092`
on the internal network, so that setting only affects tools on your host.

### Locally against containerised infrastructure

```bash
docker compose up -d redis kafka
mvn spring-boot:run
```

---

## 7. API

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/transactions` | protected demo endpoint (`payments-strict`) |
| `GET` | `/api/v1/transactions/{reference}` | protected demo lookup |
| `GET` | `/api/v1/sentinel/quota` | quota snapshot; the peek itself charges nothing |
| `GET` | `/actuator/health`, `/actuator/prometheus` | never rate limited |

The quota endpoint is rate limited like any other route, so the request that
asks for the snapshot costs its own token; `peek()` adds nothing on top. That is
deliberate: an unmetered introspection endpoint is a free denial-of-service
surface.

Every admitted response carries `X-RateLimit-Limit`, `X-RateLimit-Remaining`,
`X-RateLimit-Reset`, `X-RateLimit-Policy` (plus `X-RateLimit-Degraded` when the
decision came from an unreachable backend).

### Trip the limiter

```bash
# payments-strict allows 20 tokens / minute; the 21st call is shed
for i in $(seq 1 21); do
  curl -s -o /dev/null -w "%{http_code} " \
    -X POST http://localhost:8080/api/v1/transactions \
    -H 'Content-Type: application/json' \
    -H 'X-API-Key: demo-key-1' \
    -d '{"reference":"ref-'"$i"'","amount":125.50,"currency":"USD","beneficiary":"ACC-998877"}'
done
# 201 201 ... 201 429
```

The rejection body is an RFC 9457 problem document:

```json
{
  "type": "https://sentinelguard.satyendra.com/problems/rate-limit-exceeded",
  "title": "Too Many Requests",
  "status": 429,
  "detail": "Request quota exhausted for policy 'payments-strict'. Retry after 47 second(s).",
  "instance": "/api/v1/transactions",
  "policy": "payments-strict",
  "limit": 20,
  "remaining": 0,
  "retryAfter": 47,
  "correlationId": "7f1c…",
  "timestamp": "2026-11-07T12:34:56.789Z"
}
```

### Watch the alert arrive

```bash
docker exec -it sentinelguard-kafka /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server localhost:19092 --topic fraud-alerts --from-beginning
```

```json
{"alertId":"…","correlationId":"…","clientId":"9f86d081884c7d65…","identityType":"API_KEY",
 "clientIp":"172.18.0.1","httpMethod":"POST","path":"/api/v1/transactions",
 "policyName":"payments-strict","riskScore":70,"threatLevel":"HIGH",
 "signals":["RATE_LIMIT_BREACH","BURST_VELOCITY","MISSING_USER_AGENT"],
 "detectedAt":"2026-11-07T12:34:56.789Z"}
```

Note `clientId`: API keys and bearer tokens are reduced to a truncated SHA-256
digest **before** they are used as a Redis key or published to Kafka. Redis keys
surface in `SLOWLOG`, `MONITOR`, RDB snapshots and backups — a raw bearer token
in any of those is a credential leak, and the digest is just as unique.

---

## 8. Configuration

All keys live under `sentinelguard.*` (see `application.yml` for the shipped
defaults).

| Key | Default | Notes |
|---|---|---|
| `rate-limit.enabled` | `true` | `false` turns the filter into a pass-through |
| `rate-limit.fail-open` | `true` | behaviour when Redis is unreachable — see below |
| `rate-limit.default-policy.*` | 100 / minute | capacity, refill-tokens, refill-period, tokens-per-request, bucket-ttl |
| `rate-limit.policies.<name>.*` | — | named, reusable policies |
| `rate-limit.routes[]` | 3 routes | `path-pattern` → `policy`, **first match wins** |
| `rate-limit.identity-policies.<IdentityType>` | `ANONYMOUS` → tight | applied only when no route matched |
| `rate-limit.excluded-paths[]` | actuator, favicon | bypass entirely |
| `fraud.observation-window` | `1m` | sliding-window horizon |
| `fraud.burst-rejection-threshold` | `5` | rejections before `BURST_VELOCITY` |
| `fraud.distinct-path-threshold` | `15` | distinct paths before `PATH_ENUMERATION` |
| `fraud.publish-threshold` | `MEDIUM` | lowest band actually sent to Kafka |
| `identity.trust-forwarded-headers` | `true` | **see the warning below** |
| `alerts.topic` / `.partitions` | `fraud-alerts` / 6 | declared by the service at startup |
| `alerts.send-timeout` | `5s` | caps a single publish attempt |

Route and identity-override typos **fail the application context at startup**
rather than surfacing as a production 500 — the policy table is validated and
frozen into immutable structures in `RateLimitPolicyResolver`'s constructor.

### Two decisions worth making deliberately

**`fail-open`.** When Redis is unreachable the limiter cannot know anyone's
allowance. `true` admits the request (availability first); `false` sheds it
(protection first). Either way the verdict is flagged `degraded`, counted under
`sentinelguard.ratelimit.decisions{outcome="degraded-*"}` and logged. Payment and
authentication surfaces usually want `false`.

**`trust-forwarded-headers`.** `X-Forwarded-For` is attacker-controlled unless a
proxy in front of this service *overwrites* it. Leave it enabled only in that
topology; otherwise a caller rotates the header and mints an unlimited supply of
fresh quotas. The compose file ships it as `false`.

---

## 9. Tests

```bash
mvn test                    # unit tests only (no Docker needed)
mvn verify                  # unit + Testcontainers integration + coverage gate
mvn verify -DskipITs        # skip the Docker-backed suite
```

**Unit suite** (`*Test`, Surefire) — JUnit 5, Mockito and `StepVerifier`.
Covers argument marshalling, reply interpretation, every scoring boundary, both
degradation modes, malformed and empty backend replies, credential hashing,
header emission, the 429 body (including the serialisation-failure fallback) and
fail-fast configuration validation.

**Integration suite** (`*IT`, Failsafe) — `WebTestClient` against the real Netty
server, with a real `redis:7.4-alpine` and a real `confluentinc/cp-kafka` started
by Testcontainers. It proves what mocks cannot: that the Lua arithmetic really
behaves as a token bucket, that `PEXPIRE` housekeeping happens, that buckets are
isolated per identity, and that an alert is genuinely serialised, partitioned and
accepted by a broker — then consumed back as plain JSON (no Java `__TypeId__`
header), with the raw API key absent from the payload.

**Coverage gate** — JaCoCo enforces **≥ 90 % branch coverage** at `verify`
(`jacoco.branch.minimum`), scoped to the behavioural packages; immutable records,
enums, DTOs and Spring wiring are excluded because their synthetic
`equals`/`hashCode` branches say nothing about logic quality. The HTML report
lands in `target/site/jacoco/index.html`.

> **Build prerequisites:** `mvn` needs reachable Maven Central (or a mirror) to
> resolve dependencies, and `mvn verify` additionally needs a running Docker
> daemon for the Testcontainers suite.

---

## 10. Observability

`/actuator/prometheus` exposes, in addition to the JVM and Reactor Netty
defaults:

| Metric | Tags | Meaning |
|---|---|---|
| `sentinelguard_ratelimit_decisions_total` | `policy`, `outcome` | `allowed` / `denied` / `degraded-open` / `degraded-closed` |
| `sentinelguard_ratelimit_backend_latency` | `policy` | Redis round-trip for the admission decision |
| `sentinelguard_fraud_evaluations_total` | `outcome`, `threat` | `clean` / `suppressed` / `alerted` / `error` |
| `sentinelguard_fraud_alerts_published_total` | `outcome`, `threat` | `published` / `failed` |

A rising `degraded-*` rate is the single most important alerting signal: it means
quota decisions are no longer authoritative.

---

## 11. Production notes

* **Scaling** — the service is stateless; all quota state lives in Redis.
  Add replicas freely, the atomic script keeps one authoritative bucket.
* **Redis Cluster** — supported with no changes: every script invocation touches
  exactly one key, so it is always single-slot.
* **Clock skew** — the refill timestamp is supplied by the caller (keeping the
  script effect-free for replication and unit-testable). Nodes are assumed
  NTP-synchronised; a lagging node can never *rewind* a bucket, because a
  timestamp older than the stored watermark simply yields no refill.
* **Graceful shutdown** — `server.shutdown=graceful` plus `exec java` as PID 1,
  so SIGTERM drains in-flight exchanges instead of killing them.
* **Image size and push cost** — the layered extraction puts application classes
  in the last layer, so a code-only change re-pushes kilobytes, not the whole
  dependency set.
* **Hardening to add before exposing this publicly** — authentication
  (Spring Security on top of the existing filter order), TLS termination, and
  `management.endpoints` bound to a separate, non-public port.
