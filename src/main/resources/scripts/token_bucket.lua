--[[
  © 2026 Satyendra Singh. All Rights Reserved.
  Author: Satyendra Singh

  SentinelGuard :: Atomic Token Bucket (lazy refill)
  ---------------------------------------------------------------------------
  Redis executes every EVAL body single-threaded and atomically, therefore the
  read-modify-write cycle below cannot interleave with a competing node. This
  is what removes the classic GET/compute/SET race of a multi-replica limiter.

  KEYS[1] : bucket hash key (fields: "tokens", "ts")

  ARGV[1] : capacity              - maximum burst size, tokens
  ARGV[2] : refillTokens          - tokens granted per refill interval
  ARGV[3] : refillIntervalMillis  - length of one refill interval
  ARGV[4] : requestedTokens       - cost of this request (0 == non-mutating peek)
  ARGV[5] : nowMillis             - caller supplied wall clock, see note below
  ARGV[6] : ttlMillis             - idle expiry, keeps the keyspace self-pruning

  RETURN  : { allowed, remainingTokens, retryAfterMillis, capacity }
            allowed == 1 -> request may proceed, tokens already debited
            allowed == 0 -> request must be rejected, nothing was debited

  Clock note: the timestamp is supplied by the caller rather than read via
  redis.call('TIME') so that the script stays effect-free for replication on
  every Redis version and remains unit-testable. Application nodes are assumed
  to be NTP synchronised; a lagging node can never *rewind* a bucket because a
  timestamp older than the stored watermark simply yields no refill.
--]]

local bucketKey        = KEYS[1]

local capacity         = tonumber(ARGV[1])
local refillTokens     = tonumber(ARGV[2])
local refillIntervalMs = tonumber(ARGV[3])
local requestedTokens  = tonumber(ARGV[4])
local nowMs            = tonumber(ARGV[5])
local ttlMs            = tonumber(ARGV[6])

-- Defensive guards: a misconfigured policy must fail loudly, never silently
-- degrade into an unlimited bucket.
if capacity == nil or refillTokens == nil or refillIntervalMs == nil
        or requestedTokens == nil or nowMs == nil or ttlMs == nil then
    return redis.error_reply('SENTINELGUARD_NON_NUMERIC_ARGUMENT')
end
if capacity <= 0 or refillTokens <= 0 or refillIntervalMs <= 0 or ttlMs <= 0 then
    return redis.error_reply('SENTINELGUARD_INVALID_BUCKET_CONFIG')
end
if requestedTokens < 0 or requestedTokens > capacity then
    return redis.error_reply('SENTINELGUARD_INVALID_TOKEN_REQUEST')
end

-- ---------------------------------------------------------------------------
-- 1. Load current bucket state (a cold bucket starts full).
-- ---------------------------------------------------------------------------
local state      = redis.call('HMGET', bucketKey, 'tokens', 'ts')
local tokens     = tonumber(state[1])
local watermark  = tonumber(state[2])

if tokens == nil or watermark == nil then
    tokens    = capacity
    watermark = nowMs
end

-- ---------------------------------------------------------------------------
-- 2. Lazy refill: credit only whole elapsed intervals and carry the remainder
--    forward by advancing the watermark in exact interval multiples. Rounding
--    the watermark to "now" would leak tokens on high request rates.
-- ---------------------------------------------------------------------------
if nowMs > watermark then
    local elapsed   = nowMs - watermark
    local intervals = math.floor(elapsed / refillIntervalMs)
    if intervals > 0 then
        tokens    = math.min(capacity, tokens + (intervals * refillTokens))
        watermark = watermark + (intervals * refillIntervalMs)
    end
end

-- ---------------------------------------------------------------------------
-- 3. Admission decision.
-- ---------------------------------------------------------------------------
local allowed    = 0
local retryAfter = 0

if tokens >= requestedTokens then
    tokens  = tokens - requestedTokens
    allowed = 1
else
    -- Tell the caller exactly when the deficit will have been replenished so
    -- that it can emit a precise, non-guessing Retry-After header.
    local deficit         = requestedTokens - tokens
    local intervalsNeeded = math.ceil(deficit / refillTokens)
    retryAfter            = (watermark + (intervalsNeeded * refillIntervalMs)) - nowMs
    if retryAfter < 0 then
        retryAfter = 0
    end
end

-- ---------------------------------------------------------------------------
-- 4. Persist and refresh the idle TTL in the same atomic unit.
-- ---------------------------------------------------------------------------
redis.call('HSET', bucketKey, 'tokens', math.floor(tokens), 'ts', math.floor(watermark))
redis.call('PEXPIRE', bucketKey, ttlMs)

return { allowed, math.floor(tokens), math.floor(retryAfter), capacity }
