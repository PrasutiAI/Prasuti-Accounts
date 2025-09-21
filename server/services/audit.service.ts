import { storage } from '../storage';
import type { InsertAuditLog } from '@shared/schema';

export class AuditService {
  async log(auditData: InsertAuditLog): Promise<void> {
    try {
      await storage.createAuditLog(auditData);
    } catch (error) {
      // Log audit failures to console but don't throw to avoid breaking main operations
      console.error('Failed to create audit log:', error);
    }
  }

  async getAuditLogs(options: {
    page?: number;
    limit?: number;
    actorId?: string;
    action?: string;
    resource?: string;
    startDate?: Date;
    endDate?: Date;
  } = {}) {
    const { page = 1, limit = 50 } = options;
    const offset = (page - 1) * limit;

    // For now, use basic filtering. In production, you'd want more sophisticated filtering
    const logs = await storage.getAuditLogs(limit, offset);

    return {
      logs,
      pagination: {
        page,
        limit,
        total: logs.length, // This would be the total count in a real implementation
      },
    };
  }

  async getSecurityEvents(limit = 10) {
    const logs = await storage.getAuditLogs(limit);
    
    // Filter and format security-relevant events
    const securityEvents = logs
      .filter(log => [
        'login',
        'logout',
        'password_change',
        'mfa_enable',
        'mfa_disable',
        'user_create',
        'user_delete',
        'role_change'
      ].includes(log.action))
      .map(log => ({
        id: log.id,
        action: log.action,
        actorId: log.actorId,
        resource: log.resource,
        resourceId: log.resourceId,
        success: log.success,
        ipAddress: log.ipAddress,
        userAgent: log.userAgent,
        metadata: log.metadata,
        createdAt: log.createdAt,
      }));

    return securityEvents;
  }

  async getFailedLoginAttempts(timeWindow = 24 * 60 * 60 * 1000) { // 24 hours
    const since = new Date(Date.now() - timeWindow);
    const logs = await storage.getAuditLogs(1000); // Get more logs for analysis
    
    const failedLogins = logs
      .filter(log => 
        log.action === 'login' && 
        log.success === false &&
        new Date(log.createdAt) > since
      )
      .map(log => ({
        email: log.metadata?.email || 'unknown',
        ipAddress: log.ipAddress,
        userAgent: log.userAgent,
        reason: log.metadata?.reason || 'unknown',
        timestamp: log.createdAt,
      }));

    return {
      count: failedLogins.length,
      attempts: failedLogins,
    };
  }

  async getUserActivity(userId: string, limit = 50) {
    const logs = await storage.getAuditLogs(limit);
    
    const userLogs = logs
      .filter(log => log.actorId === userId)
      .map(log => ({
        action: log.action,
        resource: log.resource,
        success: log.success,
        ipAddress: log.ipAddress,
        metadata: log.metadata,
        timestamp: log.createdAt,
      }));

    return userLogs;
  }

  // Helper method to log common security events
  async logSecurityEvent(
    type: 'suspicious_activity' | 'brute_force' | 'unusual_location' | 'privilege_escalation',
    details: {
      actorId?: string;
      ipAddress?: string;
      userAgent?: string;
      metadata?: any;
    }
  ) {
    await this.log({
      actorId: details.actorId,
      actorType: 'system',
      action: 'login', // Generic action, specific type in metadata
      resource: 'security',
      metadata: {
        security_event_type: type,
        ...details.metadata,
      },
      ipAddress: details.ipAddress,
      userAgent: details.userAgent,
      success: false,
    });
  }
}

export const auditService = new AuditService();
