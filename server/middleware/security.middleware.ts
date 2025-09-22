import { Request, Response, NextFunction } from 'express';
import { storage } from '../storage';

// Enhanced rate limiting with different strategies
interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
  skipSuccessfulRequests?: boolean;
  keyGenerator?: (req: Request) => string;
  message?: string;
}

const rateLimitStores = new Map<string, Map<string, { count: number; resetTime: number; firstRequest: number }>>();

export function createRateLimit(config: RateLimitConfig) {
  const { windowMs, maxRequests, skipSuccessfulRequests = false, keyGenerator, message } = config;
  const storeName = `${windowMs}-${maxRequests}`;
  
  if (!rateLimitStores.has(storeName)) {
    rateLimitStores.set(storeName, new Map());
  }
  
  const store = rateLimitStores.get(storeName)!;
  
  return (req: Request, res: Response, next: NextFunction) => {
    const key = keyGenerator ? keyGenerator(req) : (req.ip || 'unknown');
    const now = Date.now();
    
    // Clean up expired entries periodically
    if (Math.random() < 0.01) { // 1% chance to clean up
      const keysToDelete: string[] = [];
      store.forEach((v, k) => {
        if (now > v.resetTime) {
          keysToDelete.push(k);
        }
      });
      keysToDelete.forEach(k => store.delete(k));
    }
    
    let clientData = store.get(key);
    
    // Reset window if expired
    if (!clientData || now > clientData.resetTime) {
      clientData = { count: 1, resetTime: now + windowMs, firstRequest: now };
      store.set(key, clientData);
      return next();
    }
    
    // Check if limit exceeded
    if (clientData.count >= maxRequests) {
      const retryAfter = Math.ceil((clientData.resetTime - now) / 1000);
      
      res.set({
        'X-RateLimit-Limit': maxRequests.toString(),
        'X-RateLimit-Remaining': '0',
        'X-RateLimit-Reset': Math.ceil(clientData.resetTime / 1000).toString(),
        'Retry-After': retryAfter.toString(),
      });
      
      return res.status(429).json({ 
        message: message || 'Too many requests',
        retryAfter: retryAfter,
        resetTime: new Date(clientData.resetTime).toISOString(),
      });
    }
    
    // Update counters
    clientData.count++;
    
    // Add rate limit headers
    res.set({
      'X-RateLimit-Limit': maxRequests.toString(),
      'X-RateLimit-Remaining': Math.max(0, maxRequests - clientData.count).toString(),
      'X-RateLimit-Reset': Math.ceil(clientData.resetTime / 1000).toString(),
    });
    
    // Skip counting successful responses if configured
    if (skipSuccessfulRequests) {
      const originalSend = res.send;
      res.send = function(body) {
        if (res.statusCode < 400) {
          clientData!.count--;
        }
        return originalSend.call(this, body);
      };
    }
    
    next();
  };
}

// Environment-specific rate limit configurations
const isDevelopment = process.env.NODE_ENV === 'development';

// Development settings: More permissive for testing and debugging
// Production settings: Strict for security
const getRateLimitConfig = () => {
  if (isDevelopment) {
    console.log('🔧 Using relaxed rate limits for development environment');
    return {
      auth: { windowMs: 15 * 60 * 1000, maxRequests: 100 }, // 100 attempts per 15 minutes
      strictAuth: { windowMs: 15 * 60 * 1000, maxRequests: 50 }, // 50 attempts per 15 minutes
      api: { windowMs: 60 * 1000, maxRequests: 1000 }, // 1000 requests per minute
      heavyApi: { windowMs: 60 * 1000, maxRequests: 100 }, // 100 requests per minute
    };
  } else {
    console.log('🔒 Using strict rate limits for production environment');
    return {
      auth: { windowMs: 15 * 60 * 1000, maxRequests: 5 }, // 5 attempts per 15 minutes
      strictAuth: { windowMs: 15 * 60 * 1000, maxRequests: 3 }, // 3 attempts per 15 minutes
      api: { windowMs: 60 * 1000, maxRequests: 100 }, // 100 requests per minute
      heavyApi: { windowMs: 60 * 1000, maxRequests: 10 }, // 10 requests per minute
    };
  }
};

const rateLimits = getRateLimitConfig();

// Different rate limit strategies with environment-specific settings
export const authRateLimit = createRateLimit({
  windowMs: rateLimits.auth.windowMs,
  maxRequests: rateLimits.auth.maxRequests,
  message: 'Too many authentication attempts',
});

export const strictAuthRateLimit = createRateLimit({
  windowMs: rateLimits.strictAuth.windowMs,
  maxRequests: rateLimits.strictAuth.maxRequests,
  message: 'Too many failed authentication attempts',
});

export const apiRateLimit = createRateLimit({
  windowMs: rateLimits.api.windowMs,
  maxRequests: rateLimits.api.maxRequests,
  skipSuccessfulRequests: true,
  message: 'API rate limit exceeded',
});

export const heavyApiRateLimit = createRateLimit({
  windowMs: rateLimits.heavyApi.windowMs,
  maxRequests: rateLimits.heavyApi.maxRequests,
  message: 'Heavy operation rate limit exceeded',
});

// User-based rate limiting for authenticated endpoints
export function createUserRateLimit(config: RateLimitConfig) {
  return createRateLimit({
    ...config,
    keyGenerator: (req: Request) => req.user?.id || req.ip || 'unknown',
  });
}

// Enhanced user-session limiting at login time
export function enforceSessionLimitAtLogin(maxSessions: number = 5) {
  return async (req: Request, res: Response, next: NextFunction) => {
    // This middleware should only be used on login endpoints
    const originalSend = res.json;
    res.json = function(body: any) {
      // If login was successful, check and cleanup sessions
      if (res.statusCode >= 200 && res.statusCode < 300 && body.refreshToken) {
        (async () => {
          try {
            // Extract user ID from the response or request
            const userId = body.user?.id;
            if (userId) {
              const activeSessions = await storage.getUserSessions(userId);
              
              // If too many sessions, revoke oldest ones (fixing off-by-one bug)
              if (activeSessions.length > maxSessions) {
                const sessionsToRevoke = activeSessions
                  .sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime())
                  .slice(0, activeSessions.length - maxSessions);
                
                for (const session of sessionsToRevoke) {
                  await storage.revokeUserSession(session.id);
                }
                
                console.log(`Revoked ${sessionsToRevoke.length} old sessions for user ${userId}`);
              }
            }
          } catch (error) {
            console.error('Error managing concurrent sessions:', error);
          }
        })();
      }
      return originalSend.call(this, body);
    };
    
    next();
  };
}

// Request sanitization middleware
export function sanitizeRequest(req: Request, res: Response, next: NextFunction) {
  // Remove potentially dangerous characters from query parameters
  for (const key in req.query) {
    if (typeof req.query[key] === 'string') {
      req.query[key] = (req.query[key] as string)
        .replace(/[<>\"']/g, '') // Remove common XSS characters
        .trim();
    }
  }
  
  // Limit query parameter values length
  for (const key in req.query) {
    if (typeof req.query[key] === 'string' && (req.query[key] as string).length > 1000) {
      return res.status(400).json({ message: 'Query parameter too long' });
    }
  }
  
  next();
}

// Security headers middleware
export function securityHeaders(req: Request, res: Response, next: NextFunction) {
  // Additional security headers beyond Helmet
  res.set({
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  });
  
  next();
}

// Request logging with security context
export function securityLogger(req: Request, res: Response, next: NextFunction) {
  const startTime = Date.now();
  
  // Log potentially suspicious requests
  const suspiciousPatterns = [
    /\.\./,              // Directory traversal
    /<script/i,          // XSS attempts
    /union.*select/i,    // SQL injection
    /javascript:/i,      // JavaScript protocol
    /vbscript:/i,       // VBScript protocol
  ];
  
  const fullUrl = req.originalUrl || req.url;
  const isSuspicious = suspiciousPatterns.some(pattern => 
    pattern.test(fullUrl) || 
    pattern.test(JSON.stringify(req.body || {})) ||
    pattern.test(JSON.stringify(req.query || {}))
  );
  
  if (isSuspicious) {
    console.warn('🚨 Suspicious request detected:', {
      method: req.method,
      url: fullUrl,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      userId: req.user?.id,
    });
  }
  
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    
    // Log failed authentication attempts
    if (req.path.includes('/auth/') && res.statusCode >= 400) {
      console.warn('🔒 Authentication failure:', {
        method: req.method,
        path: req.path,
        status: res.statusCode,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        duration,
      });
    }
    
    // Log rate limit violations
    if (res.statusCode === 429) {
      console.warn('⚡ Rate limit exceeded:', {
        method: req.method,
        path: req.path,
        ip: req.ip,
        userId: req.user?.id,
        duration,
      });
    }
  });
  
  next();
}

// Session monitoring middleware
export function sessionMonitoring(req: Request, res: Response, next: NextFunction) {
  if (req.user) {
    // Track user activity for session management
    const userId = req.user.id;
    const lastActivity = new Date();
    
    // Update last activity timestamp (could be stored in cache/database)
    // This is useful for implementing idle session timeouts
    res.locals.userActivity = {
      userId,
      lastActivity,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    };
  }
  
  next();
}