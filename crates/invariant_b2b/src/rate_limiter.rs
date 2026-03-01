// crates/invariant_b2b/src/rate_limiter.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 *
 * B2B API Token Bucket Rate Limiter.
 */

use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct RateLimiter {
    pub client: redis::Client,
}

impl RateLimiter {
    pub fn new(client: redis::Client) -> Self {
        Self { client }
    }

    pub async fn acquire(&self, user_id: &str, rate_per_sec: f64, burst_capacity: u64) -> anyhow::Result<bool> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();

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
  redis.call('EXPIRE', key, 60)
  return 0
else
  tokens = tokens - requested
  redis.call('HMSET', key, 'tokens', tokens, 'ts', ts)
  redis.call('EXPIRE', key, 60)
  return 1
end
"#;

        let key = format!("b2b_rl:{}", user_id);
        let res: i32 = redis::Script::new(script)
            .key(&key)
            .arg(rate_per_sec)
            .arg(burst_capacity)
            .arg(now)
            .arg(1)
            .invoke_async(&mut conn)
            .await?;

        Ok(res == 1)
    }
}