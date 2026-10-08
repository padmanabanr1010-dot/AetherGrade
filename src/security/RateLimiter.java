package security;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class RateLimiter {
    private static class TokenBucket {
        private final int capacity;
        private final long refillIntervalMs;
        private double tokens;
        private long lastRefillTimestamp;

        public TokenBucket(int capacity, long refillIntervalMs) {
            this.capacity = capacity;
            this.refillIntervalMs = refillIntervalMs;
            this.tokens = capacity;
            this.lastRefillTimestamp = System.currentTimeMillis();
        }

        public synchronized boolean tryConsume() {
            refill();
            if (tokens >= 1.0) {
                tokens -= 1.0;
                return true;
            }
            return false;
        }

        private void refill() {
            long now = System.currentTimeMillis();
            long elapsed = now - lastRefillTimestamp;
            if (elapsed > 0) {
                double tokensToAdd = (double) elapsed / refillIntervalMs;
                tokens = Math.min(capacity, tokens + tokensToAdd);
                lastRefillTimestamp = now;
            }
        }
    }

    private static final Map<String, TokenBucket> buckets = new ConcurrentHashMap<>();

    public static boolean allowRequest(String clientKey, int maxCapacity, long refillIntervalMs) {
        TokenBucket bucket = buckets.computeIfAbsent(clientKey, k -> new TokenBucket(maxCapacity, refillIntervalMs));
        return bucket.tryConsume();
    }
}
