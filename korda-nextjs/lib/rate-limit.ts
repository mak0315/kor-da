/**
 * Basic server-side rate limiter using an in-memory Map.
 * For true distributed setups, replace this with a Redis/Upstash implementation.
 */
interface RateLimitContext {
  tokenCount: number;
  lastRequestTime: number;
}

const rateLimiterMap = new Map<string, RateLimitContext>();

// To prevent memory leaks, we clean up the map every 5 minutes
setInterval(() => {
  const now = Date.now();
  rateLimiterMap.forEach((context, ip) => {
    if (now - context.lastRequestTime > 60000) {
      rateLimiterMap.delete(ip);
    }
  });
}, 5 * 60 * 1000);

export function isRateLimited(ip: string, limit: number, windowMs: number): boolean {
  const now = Date.now();
  const context = rateLimiterMap.get(ip) || { tokenCount: 0, lastRequestTime: now };
  
  if (now - context.lastRequestTime > windowMs) {
    context.tokenCount = 0;
    context.lastRequestTime = now;
  }
  
  context.tokenCount++;
  rateLimiterMap.set(ip, context);
  
  return context.tokenCount > limit;
}
