import { createContext, useContext, ReactNode } from 'react';
import { useAuth } from './use-auth';

// Define permission types based on the RBAC requirements
export interface Permission {
  resource: string;
  action: string;
}

export interface Role {
  id: string;
  name: string;
  permissions: string[];
  description?: string;
  isActive: boolean;
}

export interface PermissionContextType {
  hasPermission: (permission: string | Permission) => boolean;
  hasAnyPermission: (permissions: (string | Permission)[]) => boolean;
  hasAllPermissions: (permissions: (string | Permission)[]) => boolean;
  hasRole: (role: string | string[]) => boolean;
  userRole: Role | null;
  userRoleName: string | null;
  isAdmin: boolean;
  isDeveloper: boolean;
  isUser: boolean;
  isGuest: boolean;
  canAccessResource: (resource: string, action?: string) => boolean;
}

const PermissionContext = createContext<PermissionContextType | undefined>(undefined);

export function PermissionProvider({ children }: { children: ReactNode }) {
  const { user } = useAuth();

  // Convert permission string or object to string format
  const normalizePermission = (permission: string | Permission): string => {
    if (typeof permission === 'string') {
      return permission;
    }
    return `${permission.resource}:${permission.action}`;
  };

  // Check if user has a specific permission
  const hasPermission = (permission: string | Permission): boolean => {
    if (!user || !user.role) return false;

    const permissionString = normalizePermission(permission);
    const userPermissions = user.role.permissions || [];

    // Check for exact permission match
    if (userPermissions.includes(permissionString)) {
      return true;
    }

    // Check for wildcard permissions
    if (userPermissions.includes('*')) {
      return true; // Admin has all permissions
    }

    // Check for resource-level wildcard (e.g., "users:*")
    const [resource] = permissionString.split(':');
    if (userPermissions.includes(`${resource}:*`)) {
      return true;
    }

    return false;
  };

  // Check if user has any of the specified permissions
  const hasAnyPermission = (permissions: (string | Permission)[]): boolean => {
    return permissions.some(permission => hasPermission(permission));
  };

  // Check if user has all of the specified permissions
  const hasAllPermissions = (permissions: (string | Permission)[]): boolean => {
    return permissions.every(permission => hasPermission(permission));
  };

  // Check if user has a specific role
  const hasRole = (role: string | string[]): boolean => {
    if (!user || !user.role) return false;

    const roles = Array.isArray(role) ? role : [role];
    return roles.includes(user.role.name);
  };

  // Check if user can access a specific resource
  const canAccessResource = (resource: string, action: string = 'read'): boolean => {
    return hasPermission(`${resource}:${action}`);
  };

  // Get current user role information
  const userRole = user?.role || null;
  const userRoleName = user?.role?.name || null;

  // Helper boolean properties for common roles
  const isAdmin = hasRole('admin');
  const isDeveloper = hasRole(['admin', 'developer']);
  const isUser = hasRole(['admin', 'developer', 'user']);
  const isGuest = hasRole(['admin', 'developer', 'user', 'guest']);

  const value: PermissionContextType = {
    hasPermission,
    hasAnyPermission,
    hasAllPermissions,
    hasRole,
    userRole,
    userRoleName,
    isAdmin,
    isDeveloper,
    isUser,
    isGuest,
    canAccessResource,
  };

  return (
    <PermissionContext.Provider value={value}>
      {children}
    </PermissionContext.Provider>
  );
}

export function usePermissions() {
  const context = useContext(PermissionContext);
  if (context === undefined) {
    throw new Error('usePermissions must be used within a PermissionProvider');
  }
  return context;
}

// Helper hook for common permission patterns
export function useRoleCheck(requiredRole: string | string[]) {
  const { hasRole } = usePermissions();
  return hasRole(requiredRole);
}

// Helper hook for resource access
export function useResourceAccess(resource: string, action: string = 'read') {
  const { canAccessResource } = usePermissions();
  return canAccessResource(resource, action);
}

// Helper hook for multiple permissions
export function usePermissionCheck(permissions: (string | Permission)[], requireAll: boolean = false) {
  const { hasPermission, hasAllPermissions, hasAnyPermission } = usePermissions();
  
  if (permissions.length === 1) {
    return hasPermission(permissions[0]);
  }
  
  return requireAll ? hasAllPermissions(permissions) : hasAnyPermission(permissions);
}