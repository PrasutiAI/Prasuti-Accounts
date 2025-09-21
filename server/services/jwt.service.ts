import jwt from 'jsonwebtoken';
import { createPublicKey, createPrivateKey } from 'crypto';
import { storage } from '../storage';
import { cryptoUtils } from '../utils/crypto';
import type { User, JwksKey } from '@shared/schema';

interface JwtPayload {
  sub: string;
  email: string;
  name: string;
  role: string;
  iss: string;
  aud: string;
  iat: number;
  exp: number;
}

interface JwksResponse {
  keys: Array<{
    kty: string;
    use: string;
    kid: string;
    alg: string;
    n: string;
    e: string;
  }>;
}

export class JwtService {
  private readonly issuer = process.env.JWT_ISSUER || 'https://idm.prasuti.ai';
  private readonly audience = process.env.JWT_AUD || 'prasuti-services';
  private readonly accessTokenTtl = process.env.JWT_ACCESS_TTL || '15m';

  async generateAccessToken(user: User): Promise<string> {
    const activeKey = await this.getActiveSigningKey();
    if (!activeKey) {
      throw new Error('No active signing key found');
    }

    const payload: Omit<JwtPayload, 'iat' | 'exp'> = {
      sub: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      iss: this.issuer,
      aud: this.audience,
    };

    const decryptedPrivateKey = await cryptoUtils.decrypt(activeKey.privateKeyEncrypted);
    
    return jwt.sign(payload, decryptedPrivateKey, {
      algorithm: 'RS256',
      keyid: activeKey.kid,
      expiresIn: this.accessTokenTtl,
    });
  }

  async verifyToken(token: string): Promise<JwtPayload> {
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || typeof decoded === 'string') {
      throw new Error('Invalid token format');
    }

    const kid = decoded.header.kid;
    if (!kid) {
      throw new Error('Missing key ID in token header');
    }

    // Get the public key for verification
    const keys = await storage.getAllJwksKeys();
    const signingKey = keys.find(key => key.kid === kid);
    if (!signingKey) {
      throw new Error('Signing key not found');
    }

    try {
      const payload = jwt.verify(token, signingKey.publicKey, {
        algorithms: ['RS256'],
        issuer: this.issuer,
        audience: this.audience,
      }) as JwtPayload;

      return payload;
    } catch (error) {
      throw new Error(`Token verification failed: ${error.message}`);
    }
  }

  async getJwksResponse(): Promise<JwksResponse> {
    const keys = await storage.getAllJwksKeys();
    const activeKeys = keys.filter(key => key.isActive && new Date(key.expiresAt) > new Date());

    const jwksKeys = await Promise.all(
      activeKeys.map(async (key) => {
        const publicKey = createPublicKey(key.publicKey);
        const keyObject = publicKey.asymmetricKeyDetails;
        
        if (!keyObject || !keyObject.n || !keyObject.e) {
          throw new Error(`Invalid public key format for kid: ${key.kid}`);
        }

        return {
          kty: 'RSA',
          use: 'sig',
          kid: key.kid,
          alg: key.algorithm,
          n: keyObject.n.toString('base64url'),
          e: keyObject.e.toString('base64url'),
        };
      })
    );

    return { keys: jwksKeys };
  }

  async rotateKeys(): Promise<{ kid: string; publicKey: string }> {
    // Generate new RSA key pair
    const { publicKey, privateKey } = await cryptoUtils.generateRSAKeyPair();
    
    // Create new key ID based on current date
    const kid = `key-${new Date().toISOString().split('T')[0]}`;
    
    // Encrypt private key before storing
    const encryptedPrivateKey = await cryptoUtils.encrypt(privateKey);
    
    // Store new key
    const newKey = await storage.createJwksKey({
      kid,
      publicKey,
      privateKeyEncrypted: encryptedPrivateKey,
      algorithm: 'RS256',
      isActive: true,
      expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000), // 90 days
    });

    // Deactivate old keys (but don't delete for token validation)
    const existingKeys = await storage.getAllJwksKeys();
    for (const key of existingKeys) {
      if (key.kid !== kid && key.isActive) {
        await storage.deactivateJwksKey(key.kid);
      }
    }

    return {
      kid: newKey.kid,
      publicKey: newKey.publicKey,
    };
  }

  private async getActiveSigningKey(): Promise<JwksKey | undefined> {
    const activeKey = await storage.getActiveJwksKey();
    
    // Check if key is expired
    if (activeKey && new Date(activeKey.expiresAt) <= new Date()) {
      // Auto-rotate if expired
      await this.rotateKeys();
      return await storage.getActiveJwksKey();
    }
    
    return activeKey;
  }

  async validateAndDecodeToken(token: string): Promise<JwtPayload | null> {
    try {
      return await this.verifyToken(token);
    } catch (error) {
      console.error('Token validation failed:', error.message);
      return null;
    }
  }
}

export const jwtService = new JwtService();
