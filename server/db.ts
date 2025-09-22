import { Pool, neonConfig } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/neon-serverless';
import ws from "ws";
import * as schema from "@shared/schema";

neonConfig.webSocketConstructor = ws;

let _pool: Pool | null = null;
let _db: any = null;

function initializeDatabase() {
  if (!process.env.DATABASE_URL) {
    throw new Error(
      "DATABASE_URL must be set. Did you forget to provision a database?",
    );
  }

  if (!_pool) {
    _pool = new Pool({ connectionString: process.env.DATABASE_URL });
    _db = drizzle({ client: _pool, schema });
  }

  return { pool: _pool, db: _db };
}

// Lazy initialization - only connect when actually accessed
export const pool = new Proxy({} as Pool, {
  get(target, prop) {
    const { pool } = initializeDatabase();
    return (pool as any)[prop];
  }
});

export const db = new Proxy({} as any, {
  get(target, prop) {
    const { db } = initializeDatabase();
    return db[prop];
  }
});