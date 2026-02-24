// crates/invariant_server/src/rate_limiter.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 *
 * Redis-backed token bucket rate limiter implemented with a Lua script for atomicity.
 *
 * Usage:
 * let allowed = rate_limiter.acquire(api_key, rate_per_sec, burst_capacity).await?;
 */

use anyhow::Context;
use redis::Client;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

/// A small wrapper around Redis and a token-bucket Lua script.
#[derive(Clone)]
pub struct RateLimiter {
    pub client: Client,
}

impl RateLimiter {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Attempt to consume 1 token from the bucket for `api_key`.
    /// - `rate_per_sec`: allowed tokens per second (float)
    /// - `burst_capacity`: max tokens in bucket (integer)
    pub async fn acquire(&self, api_key: &str, rate_per_sec: f64, burst_capacity: u64) -> anyhow::Result<bool> {
        let mut conn = self.client.get_multiplexed_async_connection()
            .await
            .context("Failed to get Redis connection for rate limiter")?;

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();

        // Lua token-bucket script
        let script = r#"
local key = KEYS[1]
local rate = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local requested = tonumber(ARGV[4])

local data = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(data[1])
local ts = tonumber(data[2])

if tokens == nil then
  tokens = burst
  ts = now
end

local elapsed = now - ts
if elapsed > 0 then
  local refill = elapsed * rate
  tokens = math.min(burst, tokens + refill)
  ts = now
end

if tokens < requested then
  redis.call('HMSET', key, 'tokens', tokens, 'ts', ts)
  redis.call('EXPIRE', key, 3600)
  return 0
else
  tokens = tokens - requested
  redis.call('HMSET', key, 'tokens', tokens, 'ts', ts)
  redis.call('EXPIRE', key, 3600)
  return 1
end
"#;

        let key = format!("rl:{}", api_key);
        let res: i32 = redis::Script::new(script)
            .key(&key)
            .arg(rate_per_sec)
            .arg(burst_capacity)
            .arg(now)
            .arg(1)
            .invoke_async(&mut conn)
            .await
            .context("Failed to run rate limiter script")?;

        let allowed = res == 1;
        debug!(api_key = %api_key, allowed = allowed, "rate_limiter.acquire executed");
        
        Ok(allowed)
    }
}