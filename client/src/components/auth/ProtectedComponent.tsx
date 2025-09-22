import { ReactNode } from 'react';
import { usePermissions, Permission } from '@/hooks/use-permissions';

interface ProtectedComponentProps {
  children: ReactNode;
  requiredRoles?: string | string[];
  requiredPermissions?: (string | Permission)[];
  requireAllPermissions?: boolean;
  fallback?: ReactNode;
  hideOnError?: boolean;
}

export default function ProtectedComponent({
  children,
  requiredRoles,
  requiredPermissions,
  requireAllPermissions = false,
  fallback = null,
  hideOnError = false,
}: ProtectedComponentProps) {
  const { hasRole, hasAllPermissions, hasAnyPermission } = usePermissions();

  // Check role requirements
  if (requiredRoles) {
    if (!hasRole(requiredRoles)) {
      return hideOnError ? null : <>{fallback}</>;
    }
  }

  // Check permission requirements
  if (requiredPermissions) {
    const hasRequiredPermissions = requireAllPermissions
      ? hasAllPermissions(requiredPermissions)
      : hasAnyPermission(requiredPermissions);

    if (!hasRequiredPermissions) {
      return hideOnError ? null : <>{fallback}</>;
    }
  }

  // User has required permissions, render children
  return <>{children}</>;
}