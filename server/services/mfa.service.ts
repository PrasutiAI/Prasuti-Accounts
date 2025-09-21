import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import { randomBytes } from 'crypto';
import { storage } from '../storage';
import { auditService } from './audit.service';

export class MfaService {
  private readonly serviceName = 'Prasuti.AI Hub';

  async generateMfaSecret(userId: string): Promise<{
    secret: string;
    qrCode: string;
    backupCodes: string[];
  }> {
    const user = await storage.getUser(userId);
    if (!user) {
      throw new Error('User not found');
    }

    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `${this.serviceName} (${user.email})`,
      issuer: this.serviceName,
      length: 32,
    });

    // Generate QR code
    const qrCode = await QRCode.toDataURL(secret.otpauth_url!);

    // Generate backup codes
    const backupCodes = this.generateBackupCodes();

    // Store secret (but don't enable MFA yet)
    await storage.updateUser(userId, {
      mfaSecret: secret.base32,
      backupCodes,
    });

    return {
      secret: secret.base32!,
      qrCode,
      backupCodes,
    };
  }

  async enableMfa(userId: string, token: string): Promise<void> {
    const user = await storage.getUser(userId);
    if (!user || !user.mfaSecret) {
      throw new Error('MFA secret not found');
    }

    // Verify the token
    const isValid = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token,
      window: 2, // Allow 2 time steps before/after
    });

    if (!isValid) {
      throw new Error('Invalid MFA token');
    }

    // Enable MFA
    await storage.updateUser(userId, { mfaEnabled: true });

    // Log audit event
    await auditService.log({
      actorId: userId,
      action: 'mfa_enable',
      resource: 'user',
      resourceId: userId,
      success: true,
    });
  }

  async disableMfa(userId: string, token: string): Promise<void> {
    const user = await storage.getUser(userId);
    if (!user) {
      throw new Error('User not found');
    }

    if (!user.mfaEnabled) {
      throw new Error('MFA is not enabled');
    }

    // Verify current MFA token or backup code
    const isValidToken = await this.verifyToken(userId, token);
    if (!isValidToken) {
      throw new Error('Invalid MFA token or backup code');
    }

    // Disable MFA and clear secrets
    await storage.updateUser(userId, {
      mfaEnabled: false,
      mfaSecret: null,
      backupCodes: null,
    });

    // Log audit event
    await auditService.log({
      actorId: userId,
      action: 'mfa_disable',
      resource: 'user',
      resourceId: userId,
      success: true,
    });
  }

  async verifyToken(userId: string, token: string): Promise<boolean> {
    const user = await storage.getUser(userId);
    if (!user || !user.mfaEnabled || !user.mfaSecret) {
      return false;
    }

    // First try TOTP verification
    const isValidTotp = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token,
      window: 2,
    });

    if (isValidTotp) {
      return true;
    }

    // Try backup codes
    if (user.backupCodes && user.backupCodes.includes(token)) {
      // Remove used backup code
      const updatedBackupCodes = user.backupCodes.filter(code => code !== token);
      await storage.updateUser(userId, { backupCodes: updatedBackupCodes });

      // Log backup code usage
      await auditService.log({
        actorId: userId,
        action: 'login',
        resource: 'user',
        resourceId: userId,
        metadata: { backup_code_used: true },
        success: true,
      });

      return true;
    }

    return false;
  }

  async regenerateBackupCodes(userId: string, currentToken: string): Promise<string[]> {
    const user = await storage.getUser(userId);
    if (!user || !user.mfaEnabled) {
      throw new Error('MFA is not enabled');
    }

    // Verify current MFA token
    const isValid = await this.verifyToken(userId, currentToken);
    if (!isValid) {
      throw new Error('Invalid MFA token');
    }

    // Generate new backup codes
    const backupCodes = this.generateBackupCodes();
    await storage.updateUser(userId, { backupCodes });

    // Log audit event
    await auditService.log({
      actorId: userId,
      action: 'mfa_enable', // Treating as MFA update
      resource: 'user',
      resourceId: userId,
      metadata: { backup_codes_regenerated: true },
      success: true,
    });

    return backupCodes;
  }

  async getMfaStatus(userId: string): Promise<{
    enabled: boolean;
    backupCodesCount: number;
  }> {
    const user = await storage.getUser(userId);
    if (!user) {
      throw new Error('User not found');
    }

    return {
      enabled: user.mfaEnabled || false,
      backupCodesCount: user.backupCodes?.length || 0,
    };
  }

  private generateBackupCodes(): string[] {
    const codes: string[] = [];
    for (let i = 0; i < 10; i++) {
      // Generate 8-character alphanumeric codes
      const code = randomBytes(4).toString('hex').toUpperCase();
      codes.push(`${code.slice(0, 4)}-${code.slice(4, 8)}`);
    }
    return codes;
  }
}

export const mfaService = new MfaService();
