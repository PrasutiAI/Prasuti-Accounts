import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "wouter";
import Sidebar from "@/components/layout/sidebar";
import Header from "@/components/layout/header";
import MetricsCards from "@/components/dashboard/metrics-cards";
import SystemHealth from "@/components/dashboard/system-health";
import UserTable from "@/components/users/user-table";
import UserModal from "@/components/users/user-modal";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { 
  Plus, History, Download, Key, Shield, Users, Lock, 
  Zap, Eye, CheckCircle, ArrowRight, Globe, Server,
  RefreshCw, AlertTriangle, FileText, Settings,
  BarChart3, Clock, Fingerprint, Database
} from "lucide-react";

// Type interfaces for better type safety
interface MetricsData {
  users?: {
    totalUsers: number;
    activeUsers: number;
    pendingUsers: number;
    blockedUsers: number;
  };
  system?: {
    totalUsers: number;
    activeUsers: number;
    totalClients: number;
    activeKeys: number;
  };
}

interface User {
  id: string;
  email: string;
  name: string;
  role: string;
  status: string;
  isVerified: boolean;
  mfaEnabled: boolean;
  lastLogin: string | null;
  createdAt: string;
}

interface UsersResponse {
  users: User[];
}

interface AuditEvent {
  id: string;
  action: string;
  success: boolean;
  metadata?: {
    email?: string;
  };
  ipAddress?: string;
  createdAt: string;
}

export default function Dashboard() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [userModalOpen, setUserModalOpen] = useState(false);

  const { data: systemStats } = useQuery<MetricsData>({
    queryKey: ['/api/admin/stats'],
  });

  const { data: auditEvents } = useQuery<AuditEvent[]>({
    queryKey: ['/api/audit/security-events'],
  });

  const { data: usersData } = useQuery<UsersResponse>({
    queryKey: ['/api/users'],
  });

  return (
    <div className="min-h-screen flex bg-background">
      <Sidebar 
        collapsed={sidebarCollapsed} 
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
      />
      
      <div className="flex-1 flex flex-col">
        <Header onSidebarToggle={() => setSidebarCollapsed(!sidebarCollapsed)} />
        
        <main className="flex-1 overflow-auto">
          {/* Hero Section */}
          <section className="bg-gradient-to-br from-primary/5 via-background to-secondary/5 px-6 py-12 border-b">
            <div className="max-w-6xl mx-auto">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-center">
                <div className="space-y-6">
                  <div className="flex items-center space-x-2">
                    <Shield className="h-8 w-8 text-primary" />
                    <span className="text-2xl font-bold text-foreground">Prasuti.AI IDM</span>
                  </div>
                  <div className="space-y-4">
                    <h1 className="text-4xl font-bold text-foreground leading-tight" data-testid="hero-title">
                      Enterprise Identity & Access Management
                    </h1>
                    <p className="text-xl text-muted-foreground leading-relaxed" data-testid="hero-description">
                      Secure, scalable, and comprehensive identity management solution 
                      for modern applications. Built with enterprise security at its core.
                    </p>
                  </div>
                  
                  <div className="flex flex-wrap gap-3">
                    <Badge variant="secondary" className="px-3 py-1">
                      <CheckCircle className="h-4 w-4 mr-1" />
                      Production Ready
                    </Badge>
                    <Badge variant="secondary" className="px-3 py-1">
                      <Lock className="h-4 w-4 mr-1" />
                      Enterprise Security
                    </Badge>
                    <Badge variant="secondary" className="px-3 py-1">
                      <Zap className="h-4 w-4 mr-1" />
                      High Performance
                    </Badge>
                  </div>
                </div>
                
                <div className="lg:pl-8">
                  <div className="bg-card border rounded-lg p-6 shadow-sm">
                    <h3 className="text-lg font-semibold text-foreground mb-4">System Overview</h3>
                    <div className="grid grid-cols-2 gap-4">
                      <div className="text-center p-3 bg-muted/50 rounded-lg">
                        <Users className="h-8 w-8 text-primary mx-auto mb-2" />
                        <div className="text-2xl font-bold text-foreground">{systemStats?.system?.totalUsers || '0'}</div>
                        <div className="text-sm text-muted-foreground">Total Users</div>
                      </div>
                      <div className="text-center p-3 bg-muted/50 rounded-lg">
                        <Globe className="h-8 w-8 text-green-600 mx-auto mb-2" />
                        <div className="text-2xl font-bold text-foreground">{systemStats?.system?.activeUsers || '0'}</div>
                        <div className="text-sm text-muted-foreground">Active Sessions</div>
                      </div>
                      <div className="text-center p-3 bg-muted/50 rounded-lg">
                        <Key className="h-8 w-8 text-yellow-600 mx-auto mb-2" />
                        <div className="text-2xl font-bold text-foreground">{systemStats?.system?.activeKeys || '0'}</div>
                        <div className="text-sm text-muted-foreground">API Keys</div>
                      </div>
                      <div className="text-center p-3 bg-muted/50 rounded-lg">
                        <Server className="h-8 w-8 text-blue-600 mx-auto mb-2" />
                        <div className="text-2xl font-bold text-green-600">Online</div>
                        <div className="text-sm text-muted-foreground">System Status</div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </section>

          {/* Key Features Section */}
          <section className="px-6 py-12">
            <div className="max-w-6xl mx-auto">
              <div className="text-center mb-12">
                <h2 className="text-3xl font-bold text-foreground mb-4" data-testid="features-title">
                  Comprehensive Identity Management
                </h2>
                <p className="text-lg text-muted-foreground max-w-3xl mx-auto">
                  Built for enterprise scale with modern security standards and developer-friendly APIs
                </p>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {/* Authentication Features */}
                <Card className="hover:shadow-md transition-shadow">
                  <CardContent className="p-6">
                    <div className="flex items-center space-x-3 mb-4">
                      <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center">
                        <Fingerprint className="h-6 w-6 text-primary" />
                      </div>
                      <h3 className="text-lg font-semibold text-foreground">Multi-Factor Authentication</h3>
                    </div>
                    <p className="text-muted-foreground mb-4">
                      TOTP-based MFA with backup codes, QR code setup, and seamless integration for enhanced security.
                    </p>
                    <div className="flex flex-wrap gap-2">
                      <Badge variant="outline" className="text-xs">TOTP</Badge>
                      <Badge variant="outline" className="text-xs">Backup Codes</Badge>
                      <Badge variant="outline" className="text-xs">QR Setup</Badge>
                    </div>
                  </CardContent>
                </Card>

                <Card className="hover:shadow-md transition-shadow">
                  <CardContent className="p-6">
                    <div className="flex items-center space-x-3 mb-4">
                      <div className="w-12 h-12 bg-blue-100 dark:bg-blue-900 rounded-lg flex items-center justify-center">
                        <Users className="h-6 w-6 text-blue-600" />
                      </div>
                      <h3 className="text-lg font-semibold text-foreground">Role-Based Access Control</h3>
                    </div>
                    <p className="text-muted-foreground mb-4">
                      Granular permission system with customizable roles, hierarchical access control, and policy enforcement.
                    </p>
                    <div className="flex flex-wrap gap-2">
                      <Badge variant="outline" className="text-xs">RBAC</Badge>
                      <Badge variant="outline" className="text-xs">ABAC</Badge>
                      <Badge variant="outline" className="text-xs">Policies</Badge>
                    </div>
                  </CardContent>
                </Card>

                <Card className="hover:shadow-md transition-shadow">
                  <CardContent className="p-6">
                    <div className="flex items-center space-x-3 mb-4">
                      <div className="w-12 h-12 bg-green-100 dark:bg-green-900 rounded-lg flex items-center justify-center">
                        <Key className="h-6 w-6 text-green-600" />
                      </div>
                      <h3 className="text-lg font-semibold text-foreground">JWT Token Management</h3>
                    </div>
                    <p className="text-muted-foreground mb-4">
                      RS256-signed JWT tokens with automatic key rotation, refresh token support, and JWKS endpoints.
                    </p>
                    <div className="flex flex-wrap gap-2">
                      <Badge variant="outline" className="text-xs">RS256</Badge>
                      <Badge variant="outline" className="text-xs">Auto Rotation</Badge>
                      <Badge variant="outline" className="text-xs">JWKS</Badge>
                    </div>
                  </CardContent>
                </Card>

                <Card className="hover:shadow-md transition-shadow">
                  <CardContent className="p-6">
                    <div className="flex items-center space-x-3 mb-4">
                      <div className="w-12 h-12 bg-purple-100 dark:bg-purple-900 rounded-lg flex items-center justify-center">
                        <Globe className="h-6 w-6 text-purple-600" />
                      </div>
                      <h3 className="text-lg font-semibold text-foreground">OAuth2 & Social Login</h3>
                    </div>
                    <p className="text-muted-foreground mb-4">
                      Standards-compliant OAuth2 endpoints with Google integration and extensible social login framework.
                    </p>
                    <div className="flex flex-wrap gap-2">
                      <Badge variant="outline" className="text-xs">OAuth2</Badge>
                      <Badge variant="outline" className="text-xs">Google</Badge>
                      <Badge variant="outline" className="text-xs">Extensible</Badge>
                    </div>
                  </CardContent>
                </Card>

                <Card className="hover:shadow-md transition-shadow">
                  <CardContent className="p-6">
                    <div className="flex items-center space-x-3 mb-4">
                      <div className="w-12 h-12 bg-orange-100 dark:bg-orange-900 rounded-lg flex items-center justify-center">
                        <Eye className="h-6 w-6 text-orange-600" />
                      </div>
                      <h3 className="text-lg font-semibold text-foreground">Comprehensive Audit Logs</h3>
                    </div>
                    <p className="text-muted-foreground mb-4">
                      Complete activity tracking with structured logging, security events, and compliance reporting.
                    </p>
                    <div className="flex flex-wrap gap-2">
                      <Badge variant="outline" className="text-xs">Security Events</Badge>
                      <Badge variant="outline" className="text-xs">Compliance</Badge>
                      <Badge variant="outline" className="text-xs">JSON Logs</Badge>
                    </div>
                  </CardContent>
                </Card>

                <Card className="hover:shadow-md transition-shadow">
                  <CardContent className="p-6">
                    <div className="flex items-center space-x-3 mb-4">
                      <div className="w-12 h-12 bg-red-100 dark:bg-red-900 rounded-lg flex items-center justify-center">
                        <Shield className="h-6 w-6 text-red-600" />
                      </div>
                      <h3 className="text-lg font-semibold text-foreground">Advanced Security</h3>
                    </div>
                    <p className="text-muted-foreground mb-4">
                      Rate limiting, brute force protection, encryption at rest, and security headers for comprehensive protection.
                    </p>
                    <div className="flex flex-wrap gap-2">
                      <Badge variant="outline" className="text-xs">Rate Limiting</Badge>
                      <Badge variant="outline" className="text-xs">Encryption</Badge>
                      <Badge variant="outline" className="text-xs">Headers</Badge>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </div>
          </section>

          <Separator className="my-8" />

          {/* System Metrics */}
          <section className="px-6 py-8">
            <div className="max-w-6xl mx-auto">
              <h2 className="text-2xl font-bold text-foreground mb-6">System Metrics</h2>
              <MetricsCards data={systemStats} />
            </div>
          </section>

          {/* Main Dashboard Content */}
          <section className="px-6 py-8">
            <div className="max-w-6xl mx-auto">
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Recent Users */}
                <div className="lg:col-span-2">
                  <Card>
                    <CardHeader>
                      <div className="flex items-center justify-between">
                        <CardTitle className="flex items-center space-x-2">
                          <Users className="h-5 w-5" />
                          <span>Recent Users</span>
                        </CardTitle>
                        <Link href="/users">
                          <Button 
                            variant="ghost" 
                            size="sm"
                            data-testid="button-view-all-users"
                            className="text-primary hover:text-primary/80"
                          >
                            View All <ArrowRight className="ml-1 h-4 w-4" />
                          </Button>
                        </Link>
                      </div>
                    </CardHeader>
                    <CardContent>
                      <UserTable 
                        users={usersData?.users?.slice(0, 5) || []} 
                        showActions={true}
                      />
                    </CardContent>
                  </Card>
                </div>

                {/* System Status & Quick Actions */}
                <div className="space-y-6">
                  {/* System Health */}
                  <SystemHealth />

                  {/* Enhanced Quick Actions */}
                  <Card>
                    <CardHeader>
                      <CardTitle className="flex items-center space-x-2">
                        <Zap className="h-5 w-5" />
                        <span>Quick Actions</span>
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <Button 
                        className="w-full justify-start" 
                        onClick={() => setUserModalOpen(true)}
                        data-testid="button-create-user"
                      >
                        <Plus className="mr-2 h-4 w-4" />
                        Create User
                      </Button>
                      <Link href="/api-keys">
                        <Button 
                          variant="secondary" 
                          className="w-full justify-start"
                          data-testid="button-generate-api-key"
                        >
                          <Key className="mr-2 h-4 w-4" />
                          Manage API Keys
                        </Button>
                      </Link>
                      <Link href="/audit">
                        <Button 
                          variant="secondary" 
                          className="w-full justify-start"
                          data-testid="button-view-audit-logs"
                        >
                          <History className="mr-2 h-4 w-4" />
                          View Audit Logs
                        </Button>
                      </Link>
                      <Link href="/roles">
                        <Button 
                          variant="secondary" 
                          className="w-full justify-start"
                          data-testid="button-manage-roles"
                        >
                          <Shield className="mr-2 h-4 w-4" />
                          Manage Roles
                        </Button>
                      </Link>
                      <Link href="/settings">
                        <Button 
                          variant="secondary" 
                          className="w-full justify-start"
                          data-testid="button-system-settings"
                        >
                          <Settings className="mr-2 h-4 w-4" />
                          System Settings
                        </Button>
                      </Link>
                      <Button 
                        variant="outline" 
                        className="w-full justify-start"
                        data-testid="button-export-data"
                      >
                        <Download className="mr-2 h-4 w-4" />
                        Export Data
                      </Button>
                    </CardContent>
                  </Card>
                </div>
              </div>
            </div>
          </section>

          {/* Security Highlights & Recent Activity */}
          <section className="px-6 py-8 bg-muted/20">
            <div className="max-w-6xl mx-auto">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                {/* Security Highlights */}
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center space-x-2">
                      <Shield className="h-5 w-5 text-primary" />
                      <span>Security & Compliance</span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="space-y-3">
                      <div className="flex items-center space-x-3">
                        <div className="w-8 h-8 bg-green-100 dark:bg-green-900 rounded-full flex items-center justify-center">
                          <CheckCircle className="h-4 w-4 text-green-600" />
                        </div>
                        <div>
                          <p className="font-medium text-foreground">AES-256-GCM Encryption</p>
                          <p className="text-sm text-muted-foreground">Data encrypted at rest and in transit</p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-3">
                        <div className="w-8 h-8 bg-green-100 dark:bg-green-900 rounded-full flex items-center justify-center">
                          <RefreshCw className="h-4 w-4 text-green-600" />
                        </div>
                        <div>
                          <p className="font-medium text-foreground">Automated Key Rotation</p>
                          <p className="text-sm text-muted-foreground">JWT keys rotated every 90 days</p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-3">
                        <div className="w-8 h-8 bg-green-100 dark:bg-green-900 rounded-full flex items-center justify-center">
                          <Database className="h-4 w-4 text-green-600" />
                        </div>
                        <div>
                          <p className="font-medium text-foreground">PostgreSQL + Redis</p>
                          <p className="text-sm text-muted-foreground">Enterprise-grade data persistence</p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-3">
                        <div className="w-8 h-8 bg-green-100 dark:bg-green-900 rounded-full flex items-center justify-center">
                          <AlertTriangle className="h-4 w-4 text-green-600" />
                        </div>
                        <div>
                          <p className="font-medium text-foreground">Brute Force Protection</p>
                          <p className="text-sm text-muted-foreground">Rate limiting and account lockout</p>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {/* Recent Activity */}
                <Card>
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle className="flex items-center space-x-2">
                        <Clock className="h-5 w-5" />
                        <span>Recent Security Events</span>
                      </CardTitle>
                      <Link href="/audit">
                        <Button variant="ghost" size="sm" data-testid="button-view-all-events">
                          View All <ArrowRight className="ml-1 h-4 w-4" />
                        </Button>
                      </Link>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {auditEvents && auditEvents.length > 0 ? (
                      auditEvents.slice(0, 4).map((event: any) => (
                        <div 
                          key={event.id} 
                          className="flex items-start space-x-4 p-3 bg-muted/50 rounded-lg"
                          data-testid={`event-${event.id}`}
                        >
                          <div className="w-8 h-8 bg-blue-100 dark:bg-blue-900 rounded-full flex items-center justify-center flex-shrink-0">
                            {event.action === 'login' ? (
                              <Key className="h-4 w-4 text-blue-600" />
                            ) : event.action === 'register' ? (
                              <Users className="h-4 w-4 text-green-600" />
                            ) : (
                              <FileText className="h-4 w-4 text-gray-600" />
                            )}
                          </div>
                          <div className="flex-1 min-w-0">
                            <p className="text-sm text-foreground">
                              <span className="font-medium" data-testid={`event-actor-${event.id}`}>
                                {event.metadata?.email || 'System'}
                              </span>{' '}
                              {event.action === 'login' && event.success ? 'successfully logged in' : 
                               event.action === 'register' ? 'registered' :
                               event.action === 'login' && !event.success ? 'failed to login' :
                               event.action}
                            </p>
                            <div className="flex items-center space-x-4 mt-1 text-xs text-muted-foreground">
                              <span data-testid={`event-time-${event.id}`}>
                                {new Date(event.createdAt).toLocaleString()}
                              </span>
                              {event.ipAddress && (
                                <span data-testid={`event-ip-${event.id}`}>
                                  IP: {event.ipAddress}
                                </span>
                              )}
                              <Badge 
                                variant={event.success ? "default" : "destructive"} 
                                className="text-xs"
                                data-testid={`event-status-${event.id}`}
                              >
                                {event.success ? 'Success' : 'Failed'}
                              </Badge>
                            </div>
                          </div>
                        </div>
                      ))
                    ) : (
                      <div className="text-center py-8 text-muted-foreground">
                        <FileText className="h-12 w-12 mx-auto mb-3 opacity-50" />
                        <p>No security events found</p>
                        <p className="text-sm">Activity will appear here as users interact with the system</p>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </div>
            </div>
          </section>
        </main>
      </div>

      <UserModal 
        open={userModalOpen} 
        onOpenChange={setUserModalOpen}
      />
    </div>
  );
}