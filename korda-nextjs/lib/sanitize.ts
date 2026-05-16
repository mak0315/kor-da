/**
 * Server-side input sanitization.
 * Used to strip dangerous characters from input strings to prevent XSS.
 * For rich text, consider using DOMPurify on the server, but for plain text forms,
 * this covers the core HTML entities.
 */
export function sanitizeInput(input: any, max: number = 2000): string {
  if (typeof input !== 'string') {
    return String(input || '');
  }
  
  return input
    .trim()
    .replace(/<[^>]*>/g, '') // Strip HTML tags
    .replace(/javascript:/gi, '') // Strip javascript: protocol
    .replace(/on\w+\s*=/gi, '') // Strip event handlers
    .slice(0, max);
}

/**
 * Sanitizes an entire object of inputs shallowly.
 */
export function sanitizeObject<T extends Record<string, any>>(obj: T): T {
  const sanitized: any = {};
  for (const key in obj) {
    sanitized[key] = sanitizeInput(obj[key]);
  }
  return sanitized as T;
}
