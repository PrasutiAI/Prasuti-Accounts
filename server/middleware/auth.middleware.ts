import { Request, Response, NextFunction } from 'express';
import { jwtService } from '../services/jwt.service';
import { storage } from '../storage';

// Extend Request interface to include user
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        email: string;
        name: string;
        role: string;
      };
    }
  }
}

export async function authenticateToken(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  try {
    const payload = await jwtService.verifyToken(token);
    
    // Verify user still exists and is active
    const user = await storage.getUser(payload.sub);
    if (!user || !user.isActive) {
      return res.status(401).json({ message: 'User not found or inactive' });
    }

    req.user = {
      id: payload.sub,
      email: payload.email,
      name: payload.name,
      role: payload.role,
    };

    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

export function requireRole(roles: string | string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ message: 'Authentication required' });
    }

    const allowedRoles = Array.isArray(roles) ? roles : [roles];
    
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Insufficient permissions' });
    }

    next();
  };
}

export function requirePermissions(resource: string, action: string) {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ message: 'Authentication required' });
    }

    // For now, implement basic role-based permissions
    // In production, you'd check against the permissions table
    const rolePermissions: Record<string, string[]> = {
      admin: ['*'], // Admin has all permissions
      developer: ['users:read', 'clients:*', 'keys:read'],
      user: ['users:read-own', 'profile:*'],
      guest: ['users:read-own'],
    };

    const userPermissions = rolePermissions[req.user.role] || [];
    const requiredPermission = `${resource}:${action}`;
    
    const hasPermission = userPermissions.includes('*') || 
                         userPermissions.includes(requiredPermission) ||
                         userPermissions.some(perm => {
                           if (perm.endsWith(':*')) {
                             const permResource = perm.split(':')[0];
                             return permResource === resource;
                           }
                           return false;
                         });

    if (!hasPermission) {
      return res.status(403).json({ 
        message: 'Insufficient permissions',
        required: requiredPermission,
      });
    }

    next();
  };
}

// Optional authentication - sets user if token is valid but doesn't require it
export async function optionalAuth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (token) {
    try {
      const payload = await jwtService.verifyToken(token);
      const user = await storage.getUser(payload.sub);
      
      if (user && user.isActive) {
        req.user = {
          id: payload.sub,
          email: payload.email,
          name: payload.name,
          role: payload.role,
        };
      }
    } catch (error) {
      // Ignore token errors in optional auth
    }
  }

  next();
}

// Rate limiting middleware (simple implementation)
const rateLimitMap = new Map<string, { count: number; resetTime: number }>();

export function rateLimit(maxRequests = 5, windowMs = 15 * 60 * 1000) { // 5 requests per 15 minutes
  return (req: Request, res: Response, next: NextFunction) => {
    const clientId = req.ip || 'unknown';
    const now = Date.now();
    
    const clientData = rateLimitMap.get(clientId);
    
    if (!clientData || now > clientData.resetTime) {
      rateLimitMap.set(clientId, { count: 1, resetTime: now + windowMs });
      return next();
    }
    
    if (clientData.count >= maxRequests) {
      return res.status(429).json({ 
        message: 'Too many requests',
        resetTime: new Date(clientData.resetTime).toISOString(),
      });
    }
    
    clientData.count++;
    next();
  };
}
