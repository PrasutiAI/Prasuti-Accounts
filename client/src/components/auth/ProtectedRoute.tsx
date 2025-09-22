import { ReactNode } from 'react';
import { useAuth } from '@/hooks/use-auth';
import { usePermissions, Permission } from '@/hooks/use-permissions';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Shield, ArrowLeft, Home } from 'lucide-react';
import { Link } from 'wouter';

interface ProtectedRouteProps {
  children: ReactNode;
  requiredRoles?: string | string[];
  requiredPermissions?: (string | Permission)[];
  requireAllPermissions?: boolean;
  fallbackComponent?: ReactNode;
  redirectTo?: string;
  showError?: boolean;
  loadingComponent?: ReactNode;
}

interface UnauthorizedPageProps {
  requiredRoles?: string | string[];
  requiredPermissions?: (string | Permission)[];
  message?: string;
}

function UnauthorizedPage({ requiredRoles, requiredPermissions, message }: UnauthorizedPageProps) {
  const { user } = useAuth();
  
  const defaultMessage = requiredRoles 
    ? `You need ${Array.isArray(requiredRoles) ? requiredRoles.join(' or ') : requiredRoles} role to access this page.`
    : requiredPermissions 
    ? `You don't have the required permissions to access this page.`
    : `You are not authorized to access this page.`;

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="mx-auto w-12 h-12 bg-destructive/10 rounded-full flex items-center justify-center mb-4">
            <Shield className="w-6 h-6 text-destructive" />
          </div>
          <CardTitle className="text-xl">Access Denied</CardTitle>
          <CardDescription>
            {message || defaultMessage}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="text-sm text-muted-foreground space-y-2">
            {user && (
              <div>
                <p><strong>Current user:</strong> {user.name} ({user.email})</p>
                <p><strong>Current role:</strong> {user.role?.name || 'No role assigned'}</p>
              </div>
            )}
            
            {requiredRoles && (
              <p><strong>Required roles:</strong> {Array.isArray(requiredRoles) ? requiredRoles.join(', ') : requiredRoles}</p>
            )}
            
            {requiredPermissions && (
              <p><strong>Required permissions:</strong> {requiredPermissions.map(p => 
                typeof p === 'string' ? p : `${p.resource}:${p.action}`
              ).join(', ')}</p>
            )}
          </div>
          
          <div className="flex flex-col gap-2">
            <Button asChild variant="default" data-testid="button-go-home">
              <Link href="/">
                <Home className="w-4 h-4 mr-2" />
                Go to Dashboard
              </Link>
            </Button>
            <Button 
              variant="outline" 
              onClick={() => window.history.back()}
              data-testid="button-go-back"
            >
              <ArrowLeft className="w-4 h-4 mr-2" />
              Go Back
            </Button>
          </div>
          
          <div className="text-xs text-muted-foreground text-center">
            If you believe this is an error, please contact your administrator.
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function LoadingPage() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <div className="text-center space-y-4">
        <div className="w-8 h-8 border-4 border-primary border-t-transparent rounded-full animate-spin mx-auto"></div>
        <p className="text-muted-foreground">Checking permissions...</p>
      </div>
    </div>
  );
}

export default function ProtectedRoute({
  children,
  requiredRoles,
  requiredPermissions,
  requireAllPermissions = false,
  fallbackComponent,
  redirectTo,
  showError = true,
  loadingComponent,
}: ProtectedRouteProps) {
  const { user, isLoading } = useAuth();
  const { hasRole, hasPermission, hasAllPermissions, hasAnyPermission } = usePermissions();

  // Show loading state while checking authentication
  if (isLoading) {
    return loadingComponent || <LoadingPage />;
  }

  // If user is not logged in, redirect to login
  if (!user) {
    // In a real app, you might want to redirect to login page
    // For now, we'll show an unauthorized page
    return showError ? (
      <UnauthorizedPage 
        requiredRoles={requiredRoles}
        requiredPermissions={requiredPermissions}
        message="You must be logged in to access this page."
      />
    ) : null;
  }

  // Check role requirements
  if (requiredRoles) {
    if (!hasRole(requiredRoles)) {
      if (fallbackComponent) return <>{fallbackComponent}</>;
      if (!showError) return null;
      return (
        <UnauthorizedPage 
          requiredRoles={requiredRoles}
          requiredPermissions={requiredPermissions}
        />
      );
    }
  }

  // Check permission requirements
  if (requiredPermissions) {
    const hasRequiredPermissions = requireAllPermissions
      ? hasAllPermissions(requiredPermissions)
      : hasAnyPermission(requiredPermissions);

    if (!hasRequiredPermissions) {
      if (fallbackComponent) return <>{fallbackComponent}</>;
      if (!showError) return null;
      return (
        <UnauthorizedPage 
          requiredRoles={requiredRoles}
          requiredPermissions={requiredPermissions}
        />
      );
    }
  }

  // User has required permissions, render children
  return <>{children}</>;
}