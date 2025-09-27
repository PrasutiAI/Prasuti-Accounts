import { createContext, useContext, useEffect, useRef, useState, ReactNode } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { jwtDecode } from 'jwt-decode';
import { apiRequest } from '@/lib/queryClient';

interface Role {
  id: string;
  name: string;
  permissions: string[];
  description?: string;
  isActive: boolean;
}

interface User {
  id: string;
  email: string;
  name: string;
  role: Role;
}

interface AuthContextType {
  user: User | null;
  login: (credentials: { email: string; password: string; mfaCode?: string }) => Promise<void>;
  logout: () => void;
  isLoading: boolean;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Default role permissions based on role hierarchy
const getRolePermissions = (roleName: string): string[] => {
  const rolePermissions: Record<string, string[]> = {
    admin: ['*'], // Admin has all permissions
    developer: [
      'users:read', 'users:update',
      'roles:read', 'clients:*', 
      'api-keys:*', 'audit:read',
      'settings:read', 'settings:update'
    ],
    user: [
      'dashboard:read', 'profile:*',
      'settings:read'
    ],
    guest: [
      'dashboard:read'
    ],
  };
  
  return rolePermissions[roleName] || rolePermissions['guest'];
};

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const queryClient = useQueryClient();
  
  // Ref to track session refresh interval
  const sessionRefreshInterval = useRef<NodeJS.Timeout | null>(null);

  // Enhanced session management - proactive token refresh
  const setupSessionRefresh = () => {
    const token = localStorage.getItem('accessToken');
    if (!token) return;
    
    try {
      const decoded = jwtDecode(token);
      const now = Date.now() / 1000;
      const expiryTime = decoded.exp || 0;
      
      // Refresh token 5 minutes before expiry (or halfway through if token life is less than 10 minutes)
      const refreshBuffer = Math.min(300, (expiryTime - now) / 2); // 5 minutes or half the remaining time
      const refreshTime = (expiryTime - now - refreshBuffer) * 1000; // Convert to milliseconds
      
      if (refreshTime > 0) {
        // Clear existing interval
        if (sessionRefreshInterval.current) {
          clearTimeout(sessionRefreshInterval.current);
        }
        
        // Set up automatic refresh
        sessionRefreshInterval.current = setTimeout(async () => {
          await handleTokenRefresh();
          // Set up next refresh cycle
          setupSessionRefresh();
        }, refreshTime);
      }
    } catch (error) {
      console.error('Failed to setup session refresh:', error);
    }
  };

  // Clear session refresh interval
  const clearSessionRefresh = () => {
    if (sessionRefreshInterval.current) {
      clearTimeout(sessionRefreshInterval.current);
      sessionRefreshInterval.current = null;
    }
  };

  // Function to fetch user with full role data
  const fetchUserWithRole = async (userId: string): Promise<User | null> => {
    try {
      const response = await fetch(`/api/users/${userId}`, {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('accessToken')}`,
        },
      });
      
      if (response.ok) {
        const userData = await response.json();
        return {
          id: userData.id,
          email: userData.email,
          name: userData.name,
          role: userData.role || {
            id: 'default-user-role',
            name: 'user',
            permissions: getRolePermissions('user'),
            isActive: true,
          },
        };
      }
    } catch (error) {
      console.error('Failed to fetch user with role:', error);
    }
    return null;
  };

  // Check for existing token on mount
  useEffect(() => {
    const initAuth = async () => {
      const token = localStorage.getItem('accessToken');
      if (token) {
        try {
          const decoded = jwtDecode(token);
          const now = Date.now() / 1000;
          
          if (decoded.exp && decoded.exp > now) {
            // Try to fetch full user data with role
            const userData = await fetchUserWithRole(decoded.sub as string);
            
            if (userData) {
              setUser(userData);
            } else {
              // Fallback to token data if API call fails
              setUser({
                id: decoded.sub as string,
                email: (decoded as any).email,
                name: (decoded as any).name,
                role: {
                  id: 'temp-role-id',
                  name: (decoded as any).role || 'user',
                  permissions: getRolePermissions((decoded as any).role || 'user'),
                  isActive: true,
                },
              });
            }
            
            // Set up proactive session refresh
            setupSessionRefresh();
          } else {
            // Token expired, try to refresh
            await handleTokenRefresh();
          }
        } catch (error) {
          console.error('Invalid token:', error);
          localStorage.removeItem('accessToken');
          localStorage.removeItem('refreshToken');
        }
      }
      setIsLoading(false);
    };

    initAuth();
    
    // Cleanup function to clear session refresh on unmount
    return () => {
      clearSessionRefresh();
    };
  }, []);

  const handleTokenRefresh = async () => {
    const refreshToken = localStorage.getItem('refreshToken');
    if (!refreshToken) return;

    try {
      const response = await fetch('/api/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
        }),
      });

      if (response.ok) {
        const data = await response.json();
        localStorage.setItem('accessToken', data.access_token);
        localStorage.setItem('refreshToken', data.refresh_token);

        const decoded = jwtDecode(data.access_token);
        
        // Try to fetch full user data with role
        const userData = await fetchUserWithRole(decoded.sub as string);
        
        if (userData) {
          setUser(userData);
        } else {
          // Fallback to token data if API call fails
          setUser({
            id: decoded.sub as string,
            email: (decoded as any).email,
            name: (decoded as any).name,
            role: {
              id: 'temp-role-id',
              name: (decoded as any).role || 'user',
              permissions: getRolePermissions((decoded as any).role || 'user'),
              isActive: true,
            },
          });
        }
        
        // Set up proactive session refresh after successful token refresh
        setupSessionRefresh();
      } else {
        throw new Error('Refresh failed');
      }
    } catch (error) {
      console.error('Token refresh failed:', error);
      localStorage.removeItem('accessToken');
      localStorage.removeItem('refreshToken');
      setUser(null);
      clearSessionRefresh(); // Clear refresh interval on error
    }
  };

  const login = async (credentials: { email: string; password: string; mfaCode?: string }) => {
    try {
      const response = await apiRequest('POST', '/api/auth/login', credentials);
      const data = await response.json();

      localStorage.setItem('accessToken', data.accessToken);
      localStorage.setItem('refreshToken', data.refreshToken);

      // Ensure the user object has proper role data
      const userWithRole = {
        ...data.user,
        role: data.user.role || {
          id: 'default-user-role',
          name: 'user',
          permissions: getRolePermissions('user'),
          isActive: true,
        },
      };

      setUser(userWithRole);
      queryClient.invalidateQueries();
      
      // Set up proactive session refresh after successful login
      setupSessionRefresh();
    } catch (error) {
      throw error;
    }
  };

  const logout = () => {
    const refreshToken = localStorage.getItem('refreshToken');
    
    if (refreshToken) {
      // Attempt to logout on server (fire and forget)
      fetch('/api/auth/logout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken }),
      }).catch(() => {
        // Ignore logout errors
      });
    }

    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    setUser(null);
    queryClient.clear();
    
    // Clear session refresh interval on logout
    clearSessionRefresh();
  };

  const value = {
    user,
    login,
    logout,
    isLoading,
    isAuthenticated: !!user,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}