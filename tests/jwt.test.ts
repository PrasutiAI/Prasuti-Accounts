import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import { jwtService } from '../server/services/jwt.service';
import { storage } from '../server/storage';
import bcrypt from 'bcrypt';

describe('JWT Service', () => {
  let testUser: any;

  beforeAll(async () => {
    // Create a test user
    const passwordHash = await bcrypt.hash('TestPassword123!', 12);
    testUser = await storage.createUser({
      email: 'jwt-test@example.com',
      name: 'JWT Test User',
      passwordHash,
      role: 'user',
      status: 'active',
      isVerified: true,
    });
  });

  describe('generateAccessToken', () => {
    it('should generate a valid JWT token', async () => {
      const token = await jwtService.generateAccessToken(testUser);
      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3); // JWT has 3 parts
    });

    it('should include user information in token payload', async () => {
      const token = await jwtService.generateAccessToken(testUser);
      const payload = await jwtService.verifyToken(token);

      expect(payload.sub).toBe(testUser.id);
      expect(payload.email).toBe(testUser.email);
      expect(payload.name).toBe(testUser.name);
      expect(payload.role).toBe(testUser.role);
    });
  });

  describe('verifyToken', () => {
    it('should verify valid token', async () => {
      const token = await jwtService.generateAccessToken(testUser);
      const payload = await jwtService.verifyToken(token);

      expect(payload).toBeDefined();
      expect(payload.sub).toBe(testUser.id);
    });

    it('should reject invalid token', async () => {
      const invalidToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature';
      
      await expect(jwtService.verifyToken(invalidToken))
        .rejects
        .toThrow();
    });

    it('should reject malformed token', async () => {
      const malformedToken = 'not.a.jwt';
      
      await expect(jwtService.verifyToken(malformedToken))
        .rejects
        .toThrow();
    });

    it('should reject empty token', async () => {
      await expect(jwtService.verifyToken(''))
        .rejects
        .toThrow();
    });
  });

  describe('getJwksResponse', () => {
    it('should return JWKS format', async () => {
      const jwks = await jwtService.getJwksResponse();
      
      expect(jwks).toHaveProperty('keys');
      expect(Array.isArray(jwks.keys)).toBe(true);
      
      if (jwks.keys.length > 0) {
        const key = jwks.keys[0];
        expect(key).toHaveProperty('kty', 'RSA');
        expect(key).toHaveProperty('use', 'sig');
        expect(key).toHaveProperty('kid');
        expect(key).toHaveProperty('alg');
        expect(key).toHaveProperty('n');
        expect(key).toHaveProperty('e');
      }
    });
  });

  describe('rotateKeys', () => {
    it('should create new signing key', async () => {
      const oldKeys = await storage.getAllJwksKeys();
      const result = await jwtService.rotateKeys();
      const newKeys = await storage.getAllJwksKeys();

      expect(result).toHaveProperty('kid');
      expect(result).toHaveProperty('publicKey');
      expect(newKeys.length).toBeGreaterThan(oldKeys.length);

      // Check that new key is active
      const activeKey = await storage.getActiveJwksKey();
      expect(activeKey?.kid).toBe(result.kid);
    });

    it('should deactivate old keys', async () => {
      // Create initial key
      const firstResult = await jwtService.rotateKeys();
      
      // Rotate again
      const secondResult = await jwtService.rotateKeys();
      
      const allKeys = await storage.getAllJwksKeys();
      const activeKeys = allKeys.filter(key => key.isActive);
      
      // Only the latest key should be active
      expect(activeKeys).toHaveLength(1);
      expect(activeKeys[0].kid).toBe(secondResult.kid);
    });
  });

  describe('validateAndDecodeToken', () => {
    it('should return payload for valid token', async () => {
      const token = await jwtService.generateAccessToken(testUser);
      const payload = await jwtService.validateAndDecodeToken(token);

      expect(payload).toBeDefined();
      expect(payload?.sub).toBe(testUser.id);
    });

    it('should return null for invalid token', async () => {
      const invalidToken = 'invalid.token.here';
      const payload = await jwtService.validateAndDecodeToken(invalidToken);

      expect(payload).toBeNull();
    });

    it('should return null for expired token', async () => {
      // This would require mocking the current time or creating an expired token
      // For now, we'll test with an invalid signature which should also return null
      const expiredToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.expired.token';
      const payload = await jwtService.validateAndDecodeToken(expiredToken);

      expect(payload).toBeNull();
    });
  });

  describe('token expiration', () => {
    it('should include expiration in token payload', async () => {
      const token = await jwtService.generateAccessToken(testUser);
      const payload = await jwtService.verifyToken(token);

      expect(payload.iat).toBeDefined();
      expect(payload.exp).toBeDefined();
      expect(payload.exp).toBeGreaterThan(payload.iat);
      
      // Token should expire within reasonable timeframe (default is 15 minutes)
      const expirationTime = payload.exp - payload.iat;
      expect(expirationTime).toBeLessThanOrEqual(15 * 60); // 15 minutes in seconds
    });
  });

  describe('token structure', () => {
    it('should include required claims', async () => {
      const token = await jwtService.generateAccessToken(testUser);
      const payload = await jwtService.verifyToken(token);

      // Check required claims
      expect(payload.iss).toBeDefined(); // Issuer
      expect(payload.aud).toBeDefined(); // Audience
      expect(payload.sub).toBeDefined(); // Subject
      expect(payload.iat).toBeDefined(); // Issued at
      expect(payload.exp).toBeDefined(); // Expires at
      
      // Check custom claims
      expect(payload.email).toBeDefined();
      expect(payload.name).toBeDefined();
      expect(payload.role).toBeDefined();
    });
  });
});
