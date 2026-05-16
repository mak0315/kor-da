/**
 * Server-side input sanitization.
 * Used to strip dangerous characters from input strings to prevent XSS.
 * For rich text, consider using DOMPurify on the server, but for plain text forms,
 * this covers the core HTML entities.
 */
export function sanitizeInput(input: any): string {
  if (typeof input !== 'string') {
    return input;
  }
  
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .trim();
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
