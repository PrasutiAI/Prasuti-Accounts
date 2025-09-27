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
import OAuthSuccess from "@/pages/oauth-success";
import Users from "@/pages/users";
import Settings from "@/pages/settings";
import Roles from "@/pages/roles";
import ApiKeys from "@/pages/api-keys";
import MFA from "@/pages/mfa";
import Audit from "@/pages/audit";
import NotFound from "@/pages/not-found";
import { AuthProvider } from "@/hooks/use-auth";
import { PermissionProvider } from "@/hooks/use-permissions";
import { ThemeProvider } from "@/hooks/use-theme";
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
      
      {/* Dashboard route - same as root */}
      <Route path="/dashboard" component={() => (
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
      <Route path="/oauth/success" component={OAuthSuccess} />
      
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
          <Roles />
        </ProtectedRoute>
      )} />
      
      <Route path="/api-keys" component={() => (
        <ProtectedRoute 
          requiredRoles={['admin', 'developer']}
          requiredPermissions={['api-keys:read']}
        >
          <ApiKeys />
        </ProtectedRoute>
      )} />
      
      <Route path="/mfa" component={() => (
        <ProtectedRoute requiredRoles={['admin', 'developer', 'user']}>
          <MFA />
        </ProtectedRoute>
      )} />
      
      <Route path="/audit" component={() => (
        <ProtectedRoute 
          requiredRoles={['admin', 'developer']}
          requiredPermissions={['audit:read']}
        >
          <Audit />
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
      <ThemeProvider>
        <AuthProvider>
          <PermissionProvider>
            <TooltipProvider>
              <Toaster />
              <Router />
            </TooltipProvider>
          </PermissionProvider>
        </AuthProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;