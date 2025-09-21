import { createCipheriv, createDecipheriv, generateKeyPair, randomBytes } from 'crypto';
import { promisify } from 'util';

const generateKeyPairAsync = promisify(generateKeyPair);

class CryptoUtils {
  private readonly algorithm = 'aes-256-gcm';
  private readonly masterKey: string;

  constructor() {
    this.masterKey = process.env.ENCRYPTION_MASTER_KEY || 'change-me-in-production';
    if (this.masterKey === 'change-me-in-production') {
      console.warn('WARNING: Using default encryption key. Set ENCRYPTION_MASTER_KEY in production!');
    }
  }

  private getKey(): Buffer {
    // In production, use a proper key derivation function (PBKDF2, scrypt, etc.)
    return Buffer.from(this.masterKey.padEnd(32, '0').slice(0, 32));
  }

  async encrypt(plaintext: string): Promise<string> {
    const iv = randomBytes(12); // 96 bits for GCM
    const cipher = createCipheriv(this.algorithm, this.getKey(), iv);
    
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    // Return iv + authTag + encrypted data, all hex encoded
    return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
  }

  async decrypt(encryptedData: string): Promise<string> {
    const parts = encryptedData.split(':');
    if (parts.length !== 3) {
      throw new Error('Invalid encrypted data format');
    }

    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const encrypted = parts[2];

    const decipher = createDecipheriv(this.algorithm, this.getKey(), iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  async generateRSAKeyPair(): Promise<{ publicKey: string; privateKey: string }> {
    const { publicKey, privateKey } = await generateKeyPairAsync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      },
    });

    return { publicKey, privateKey };
  }

  generateRandomToken(length = 32): string {
    return randomBytes(length).toString('hex');
  }

  generateApiKey(): string {
    // Generate a more readable API key format
    const prefix = 'pak'; // Prasuti API Key
    const timestamp = Date.now().toString(36);
    const random = randomBytes(16).toString('hex');
    return `${prefix}_${timestamp}_${random}`;
  }

  hashApiKey(apiKey: string): string {
    // Use a simple hash for API keys (in production, use bcrypt or similar)
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(apiKey).digest('hex');
  }

  verifyApiKey(apiKey: string, hashedKey: string): boolean {
    const hashedInput = this.hashApiKey(apiKey);
    return hashedInput === hashedKey;
  }
}

export const cryptoUtils = new CryptoUtils();
