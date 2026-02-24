// crates/invariant_server/src/circuit_breaker.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 *
 * Distributed Circuit Breaker pattern backed by Redis Lua scripting.
 * Protects heavy cryptographic and database routes from brute-force/fuzzing abuse.
 */

use anyhow::Context;
use redis::Client;
use tracing::{warn, debug};

#[derive(Clone)]
pub struct CircuitBreaker {
    pub client: Client,
    pub threshold: u32,
    pub window_secs: u32,
    pub cooldown_secs: u32,
}

impl CircuitBreaker {
    pub fn new(client: Client, threshold: u32, window_secs: u32, cooldown_secs: u32) -> Self {
        Self { client, threshold, window_secs, cooldown_secs }
    }

    /// Fast check to see if the client is currently in an OPEN (tripped) state.
    pub async fn is_tripped(&self, api_key: &str) -> anyhow::Result<bool> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .context("Failed to get Redis connection for circuit breaker")?;
        
        let trip_key = format!("cb:tripped:{}", api_key);
        let is_tripped: bool = redis::cmd("EXISTS")
            .arg(&trip_key)
            .query_async(&mut conn)
            .await
            .context("Failed to check circuit breaker state")?;
            
        Ok(is_tripped)
    }

    /// Records a critical failure. If the failure count exceeds the threshold 
    /// within the window, the circuit breaker trips and sets a cooldown.
    pub async fn record_failure(&self, api_key: &str) -> anyhow::Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .context("Failed to get Redis connection for circuit breaker")?;

        let script = r#"
        local fail_key = KEYS[1]
        local trip_key = KEYS[2]
        local threshold = tonumber(ARGV[1])
        local window = tonumber(ARGV[2])
        local cooldown = tonumber(ARGV[3])

        local fails = redis.call('INCR', fail_key)
        if fails == 1 then
            redis.call('EXPIRE', fail_key, window)
        end

        if fails >= threshold then
            redis.call('SET', trip_key, '1', 'EX', cooldown)
            redis.call('DEL', fail_key) -- Reset counter after tripping
            return 1 -- Tripped
        end
        return 0 -- Not tripped
        "#;

        let fail_key = format!("cb:fails:{}", api_key);
        let trip_key = format!("cb:tripped:{}", api_key);

        let tripped: i32 = redis::Script::new(script)
            .key(&fail_key)
            .key(&trip_key)
            .arg(self.threshold)
            .arg(self.window_secs)
            .arg(self.cooldown_secs)
            .invoke_async(&mut conn)
            .await
            .context("Circuit breaker Lua script failed")?;

        if tripped == 1 {
            warn!(
                api_key = %api_key, 
                cooldown = self.cooldown_secs, 
                "🔴 CIRCUIT BREAKER TRIPPED: Volumetric failures detected."
            );
        } else {
            debug!(api_key = %api_key, "Circuit breaker recorded failure.");
        }

        Ok(())
    }

    /// Resets the failure counter on a successful, high-trust action.
    pub async fn record_success(&self, api_key: &str) -> anyhow::Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let fail_key = format!("cb:fails:{}", api_key);
        let _: () = redis::cmd("DEL").arg(&fail_key).query_async(&mut conn).await?;
        Ok(())
    }
}