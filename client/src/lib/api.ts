import { queryClient } from "./queryClient";

interface ApiResponse<T = any> {
  data?: T;
  message?: string;
  error?: string;
}

class ApiClient {
  private baseURL = '';

  private async request<T = any>(
    method: string,
    endpoint: string,
    data?: any,
    options: RequestInit = {}
  ): Promise<ApiResponse<T>> {
    const url = `${this.baseURL}${endpoint}`;
    
    const config: RequestInit = {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      ...options,
    };

    // Add auth token if available
    const token = localStorage.getItem('accessToken');
    if (token) {
      config.headers = {
        ...config.headers,
        Authorization: `Bearer ${token}`,
      };
    }

    if (data && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
      config.body = JSON.stringify(data);
    }

    try {
      const response = await fetch(url, config);
      
      // Handle token refresh
      if (response.status === 401 && token) {
        const refreshToken = localStorage.getItem('refreshToken');
        if (refreshToken) {
          try {
            const refreshResponse = await fetch('/api/oauth/token', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                grant_type: 'refresh_token',
                refresh_token: refreshToken,
              }),
            });

            if (refreshResponse.ok) {
              const refreshData = await refreshResponse.json();
              localStorage.setItem('accessToken', refreshData.access_token);
              localStorage.setItem('refreshToken', refreshData.refresh_token);

              // Retry original request with new token
              config.headers = {
                ...config.headers,
                Authorization: `Bearer ${refreshData.access_token}`,
              };
              
              const retryResponse = await fetch(url, config);
              const retryData = await retryResponse.json();
              
              if (!retryResponse.ok) {
                throw new Error(retryData.message || `HTTP ${retryResponse.status}`);
              }
              
              return { data: retryData };
            }
          } catch (refreshError) {
            // Refresh failed, redirect to login
            localStorage.removeItem('accessToken');
            localStorage.removeItem('refreshToken');
            window.location.href = '/login';
            throw refreshError;
          }
        }
      }

      const responseData = await response.json();
      
      if (!response.ok) {
        throw new Error(responseData.message || `HTTP ${response.status}`);
      }

      return { data: responseData };
    } catch (error) {
      console.error('API request failed:', error);
      throw error;
    }
  }

  // Auth methods
  async login(credentials: { email: string; password: string; mfaCode?: string }) {
    return this.request('POST', '/api/auth/login', credentials);
  }

  async logout(refreshToken: string) {
    return this.request('POST', '/api/auth/logout', { refreshToken });
  }

  async register(userData: any) {
    return this.request('POST', '/api/auth/register', userData);
  }

  async verifyEmail(token: string) {
    return this.request('POST', '/api/auth/verify', { token });
  }

  async requestPasswordReset(email: string) {
    return this.request('POST', '/api/auth/forgot-password', { email });
  }

  async resetPassword(token: string, password: string) {
    return this.request('POST', '/api/auth/reset-password', { token, password });
  }

  // User methods
  async getUsers(page = 1, limit = 50) {
    return this.request('GET', `/api/users?page=${page}&limit=${limit}`);
  }

  async getUser(id: string) {
    return this.request('GET', `/api/users/${id}`);
  }

  async createUser(userData: any) {
    return this.request('POST', '/api/users', userData);
  }

  async updateUser(id: string, updates: any) {
    return this.request('PATCH', `/api/users/${id}`, updates);
  }

  async deleteUser(id: string) {
    return this.request('DELETE', `/api/users/${id}`);
  }

  // Admin methods
  async getSystemStats() {
    return this.request('GET', '/api/admin/stats');
  }

  async rotateKeys() {
    return this.request('POST', '/api/admin/keys/rotate');
  }

  // MFA methods
  async setupMfa() {
    return this.request('GET', '/api/mfa/setup');
  }

  async enableMfa(mfaCode: string) {
    return this.request('POST', '/api/mfa/enable', { mfaCode });
  }

  async disableMfa(mfaCode: string) {
    return this.request('POST', '/api/mfa/disable', { mfaCode });
  }

  async getMfaStatus() {
    return this.request('GET', '/api/mfa/status');
  }

  // Clients methods
  async getClients() {
    return this.request('GET', '/api/clients');
  }

  async createClient(clientData: any) {
    return this.request('POST', '/api/clients', clientData);
  }

  // Audit methods
  async getAuditLogs(page = 1, limit = 50) {
    return this.request('GET', `/api/audit?page=${page}&limit=${limit}`);
  }

  async getSecurityEvents() {
    return this.request('GET', '/api/audit/security-events');
  }

  // System methods
  async getHealth() {
    return this.request('GET', '/health');
  }

  async getMetrics() {
    return this.request('GET', '/metrics');
  }

  async getJwks() {
    return this.request('GET', '/.well-known/jwks.json');
  }
}

export const api = new ApiClient();
export default api;
