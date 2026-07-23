import jwt from 'jsonwebtoken';

/**
 * Server-only JWT utility.
 * The jsonwebtoken package and the JWT_SECRET are strictly kept out of the client bundle.
 */

export function signToken(payload: object, expiresIn: string = '1d'): string {
  const secret = process.env.JWT_SECRET;
  
  if (!secret) {
    // Proper error throwing instead of process.exit(1)
    throw new Error('FATAL: JWT_SECRET environment variable is not configured.');
  }
  
  return jwt.sign(payload, secret, { expiresIn });
}

export function verifyToken(token: string): any {
  const secret = process.env.JWT_SECRET;
  
  if (!secret) {
    throw new Error('FATAL: JWT_SECRET environment variable is not configured.');
  }
  
  try {
    return jwt.verify(token, secret);
  } catch (error) {
    throw new Error('Invalid or expired token');
  }
}
