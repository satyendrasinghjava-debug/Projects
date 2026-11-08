--[[
  © 2026 Satyendra Singh. All Rights Reserved.
  Author: Satyendra Singh

  SentinelGuard :: Atomic Sliding Window Cardinality Counter
  ---------------------------------------------------------------------------
  Backs the behavioural fraud heuristics. A sorted set scored by event time
  gives a true sliding window (not a bucketed approximation) and, because
  ZADD overwrites an existing member, the returned ZCARD is a *distinct*
  member count. That single primitive serves both heuristics:

    * velocity        -> unique member per event  => count == event volume
    * path enumeration-> member is the URI path   => count == distinct paths

  KEYS[1] : sorted set key
  ARGV[1] : nowMillis
  ARGV[2] : windowMillis  - observation horizon
  ARGV[3] : member        - event identity
  ARGV[4] : ttlMillis     - idle expiry for the window key

  RETURN  : number of distinct members inside the window, including this event
--]]

local windowKey = KEYS[1]
local nowMs     = tonumber(ARGV[1])
local windowMs  = tonumber(ARGV[2])
local member    = ARGV[3]
local ttlMs     = tonumber(ARGV[4])

if nowMs == nil or windowMs == nil or ttlMs == nil then
    return redis.error_reply('SENTINELGUARD_NON_NUMERIC_ARGUMENT')
end
if windowMs <= 0 or ttlMs <= 0 then
    return redis.error_reply('SENTINELGUARD_INVALID_WINDOW_CONFIG')
end

-- Evict everything that has aged out, admit the current event, then measure.
redis.call('ZREMRANGEBYSCORE', windowKey, '-inf', nowMs - windowMs)
redis.call('ZADD', windowKey, nowMs, member)
redis.call('PEXPIRE', windowKey, ttlMs)

return redis.call('ZCARD', windowKey)
