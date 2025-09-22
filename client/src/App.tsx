import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import Dashboard from "@/pages/dashboard";
import Login from "@/pages/login";
import Register from "@/pages/register";
import ForgotPassword from "@/pages/forgot-password";
import ResetPassword from "@/pages/reset-password";
import VerifyEmail from "@/pages/verify-email";
import Users from "@/pages/users";
import Settings from "@/pages/settings";
import NotFound from "@/pages/not-found";
import { AuthProvider } from "@/hooks/use-auth";
import { PermissionProvider } from "@/hooks/use-permissions";
import ProtectedRoute from "@/components/auth/ProtectedRoute";

function Router() {
  return (
    <Switch>
      {/* Dashboard - accessible to all authenticated users */}
      <Route path="/" component={() => (
        <ProtectedRoute requiredRoles={['admin', 'developer', 'user', 'guest']}>
          <Dashboard />
        </ProtectedRoute>
      )} />
      
      {/* Public authentication routes */}
      <Route path="/login" component={Login} />
      <Route path="/register" component={Register} />
      <Route path="/forgot-password" component={ForgotPassword} />
      <Route path="/reset-password" component={ResetPassword} />
      <Route path="/verify-email" component={VerifyEmail} />
      
      {/* Users page - admin and developer access */}
      <Route path="/users" component={() => (
        <ProtectedRoute 
          requiredRoles={['admin', 'developer']}
          requiredPermissions={['users:read']}
        >
          <Users />
        </ProtectedRoute>
      )} />
      
      {/* Settings page - authenticated users can view, but different permissions for different sections */}
      <Route path="/settings" component={() => (
        <ProtectedRoute requiredRoles={['admin', 'developer', 'user']}>
          <Settings />
        </ProtectedRoute>
      )} />
      
      {/* Admin-only routes */}
      <Route path="/roles" component={() => (
        <ProtectedRoute 
          requiredRoles="admin"
          requiredPermissions={['roles:read']}
        >
          {/* We'll create this component later if it doesn't exist */}
          <div className="p-6">
            <h1 className="text-2xl font-bold">Role Management</h1>
            <p className="text-muted-foreground">Manage user roles and permissions (Admin only)</p>
          </div>
        </ProtectedRoute>
      )} />
      
      <Route path="/api-keys" component={() => (
        <ProtectedRoute 
          requiredRoles={['admin', 'developer']}
          requiredPermissions={['api-keys:read']}
        >
          <div className="p-6">
            <h1 className="text-2xl font-bold">API Keys</h1>
            <p className="text-muted-foreground">Manage API keys and client credentials</p>
          </div>
        </ProtectedRoute>
      )} />
      
      <Route path="/mfa" component={() => (
        <ProtectedRoute requiredRoles={['admin', 'developer', 'user']}>
          <div className="p-6">
            <h1 className="text-2xl font-bold">Multi-Factor Authentication</h1>
            <p className="text-muted-foreground">Configure your MFA settings</p>
          </div>
        </ProtectedRoute>
      )} />
      
      <Route path="/audit" component={() => (
        <ProtectedRoute 
          requiredRoles={['admin', 'developer']}
          requiredPermissions={['audit:read']}
        >
          <div className="p-6">
            <h1 className="text-2xl font-bold">Audit Logs</h1>
            <p className="text-muted-foreground">View system audit logs and security events</p>
          </div>
        </ProtectedRoute>
      )} />
      
      {/* Fallback route */}
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <PermissionProvider>
          <TooltipProvider>
            <Toaster />
            <Router />
          </TooltipProvider>
        </PermissionProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
}

export default App;