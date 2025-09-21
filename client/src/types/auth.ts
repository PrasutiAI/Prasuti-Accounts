export interface User {
  id: string;
  email: string;
  name: string;
  role: 'admin' | 'developer' | 'user' | 'guest';
  status: 'active' | 'inactive' | 'pending' | 'blocked';
  isVerified: boolean;
  mfaEnabled: boolean;
  lastLogin: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface LoginRequest {
  email: string;
  password: string;
  mfaCode?: string;
}

export interface LoginResponse {
  user: User;
  accessToken: string;
  refreshToken: string;
}

export interface RegisterRequest {
  email: string;
  password: string;
  name: string;
  role?: 'admin' | 'developer' | 'user' | 'guest';
  status?: 'active' | 'inactive' | 'pending' | 'blocked';
}

export interface RefreshTokenRequest {
  refreshToken: string;
}

export interface RefreshTokenResponse {
  accessToken: string;
  refreshToken: string;
}

export interface VerifyEmailRequest {
  token: string;
}

export interface ResetPasswordRequest {
  token: string;
  password: string;
}

export interface ChangePasswordRequest {
  currentPassword: string;
  newPassword: string;
}

export interface MfaSetupResponse {
  secret: string;
  qrCode: string;
  backupCodes: string[];
}

export interface MfaStatusResponse {
  enabled: boolean;
  backupCodesCount: number;
}

export interface Client {
  id: string;
  clientId: string;
  name: string;
  grantTypes: string[];
  scopes: string[];
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface CreateClientRequest {
  name: string;
  grantTypes?: string[];
  scopes?: string[];
}

export interface AuditLog {
  id: string;
  actorId: string | null;
  actorType: 'user' | 'system' | 'client';
  action: string;
  resource: string;
  resourceId: string | null;
  metadata: Record<string, any> | null;
  ipAddress: string | null;
  userAgent: string | null;
  success: boolean;
  createdAt: string;
}

export interface SystemMetrics {
  totalUsers: number;
  activeUsers: number;
  totalClients: number;
  activeKeys: number;
  recentAuditLogs: AuditLog[];
}

export interface UserStats {
  totalUsers: number;
  activeUsers: number;
  pendingUsers: number;
  blockedUsers: number;
  usersByRole: Record<string, number>;
  mfaEnabledUsers: number;
}

export interface JwtPayload {
  sub: string;
  email: string;
  name: string;
  role: string;
  iss: string;
  aud: string;
  iat: number;
  exp: number;
}

export interface JwksKey {
  kid: string;
  kty: string;
  use: string;
  alg: string;
  n: string;
  e: string;
}

export interface JwksResponse {
  keys: JwksKey[];
}

export interface OAuth2TokenRequest {
  grant_type: 'password' | 'refresh_token' | 'client_credentials';
  username?: string;
  password?: string;
  refresh_token?: string;
  client_id?: string;
  client_secret?: string;
  scope?: string;
}

export interface OAuth2TokenResponse {
  access_token: string;
  refresh_token?: string;
  token_type: string;
  expires_in: number;
  scope?: string;
}
