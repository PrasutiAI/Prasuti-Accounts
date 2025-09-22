import 'dotenv/config';
import express, { type Request, Response, NextFunction } from "express";
import helmet from "helmet";
import { registerRoutes } from "./routes";
import { setupVite, serveStatic, log } from "./vite";
import { setupDatabase } from "../scripts/setup-database";
import { 
  securityHeaders, 
  securityLogger, 
  sanitizeRequest, 
  sessionMonitoring 
} from "./middleware/security.middleware";

const app = express();

// Trust proxy for rate limiting and IP detection
app.set('trust proxy', 1);

// Security headers - adjust CSP for development vs production
const isDevelopment = app.get("env") === "development";
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: isDevelopment 
        ? ["'self'", "'unsafe-inline'", "'unsafe-eval'"] // Allow Vite's inline scripts and eval in dev
        : ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: isDevelopment 
        ? ["'self'", "ws:", "wss:"] // Allow WebSocket connections for Vite HMR
        : ["'self'"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
  referrerPolicy: { policy: "strict-origin-when-cross-origin" }
}));

// Additional security headers
app.use(securityHeaders);

// Request sanitization
app.use(sanitizeRequest);

// Security logging
app.use(securityLogger);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: false, limit: '10mb' }));

app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;

  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      // Only log response body for non-sensitive endpoints in development
      if (capturedJsonResponse && process.env.NODE_ENV !== 'production') {
        const sensitiveEndpoints = ['/api/auth/login', '/api/auth/register', '/api/oauth/token', '/api/mfa', '/api/clients'];
        const isSensitiveEndpoint = sensitiveEndpoints.some(endpoint => path.startsWith(endpoint));
        if (!isSensitiveEndpoint) {
          logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
        } else {
          logLine += ` :: [SENSITIVE DATA HIDDEN]`;
        }
      }

      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "…";
      }

      log(logLine);
    }
  });

  next();
});

(async () => {
  // Setup database on application startup
  console.log('🚀 Starting application...');
  
  const setupSuccess = await setupDatabase({ 
    verbose: process.env.NODE_ENV === 'development' 
  });
  
  if (!setupSuccess) {
    console.error('❌ Database setup failed. Exiting...');
    process.exit(1);
  }

  const server = await registerRoutes(app);

  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    res.status(status).json({ message });
    throw err;
  });

  // importantly only setup vite in development and after
  // setting up all the other routes so the catch-all route
  // doesn't interfere with the other routes
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  // ALWAYS serve the app on the port specified in the environment variable PORT
  // Other ports are firewalled. Default to 5000 if not specified.
  // this serves both the API and the client.
  // It is the only port that is not firewalled.
  const port = parseInt(process.env.PORT || '5000', 10);
  server.listen({
    port,
    host: "0.0.0.0",
    reusePort: true,
  }, () => {
    log(`serving on port ${port}`);
  });

  // Graceful shutdown handling
  const gracefulShutdown = async (signal: string) => {
    log(`Received ${signal}. Starting graceful shutdown...`);
    
    try {
      // Close the HTTP server with timeout
      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('Server close timeout'));
        }, 10000); // 10 second timeout

        server.close((err) => {
          clearTimeout(timeout);
          if (err) {
            log(`Error closing server: ${err.message}`);
            reject(err);
          } else {
            log('HTTP server closed successfully');
            resolve();
          }
        });
      });

      // Close database connection pool after server is closed
      try {
        const { pool } = await import('./db');
        await pool.end();
        log('Database connections closed successfully');
      } catch (error) {
        log('Database connection may not have been established');
      }

      log('Graceful shutdown completed');
      process.exit(0);
    } catch (error) {
      log(`Error during graceful shutdown: ${error instanceof Error ? error.message : String(error)}`);
      // Force exit if graceful shutdown fails
      setTimeout(() => process.exit(1), 1000);
    }
  };

  // Register signal handlers
  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));

  // Handle uncaught exceptions and unhandled promise rejections
  process.on('uncaughtException', (error) => {
    log(`Uncaught Exception: ${error.message}`);
    gracefulShutdown('UNCAUGHT_EXCEPTION');
  });

  process.on('unhandledRejection', (reason, promise) => {
    log(`Unhandled Rejection at: ${promise}, reason: ${reason}`);
    gracefulShutdown('UNHANDLED_REJECTION');
  });

})();
