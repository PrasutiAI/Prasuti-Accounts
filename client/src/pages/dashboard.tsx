import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import Sidebar from "@/components/layout/sidebar";
import Header from "@/components/layout/header";
import MetricsCards from "@/components/dashboard/metrics-cards";
import SystemHealth from "@/components/dashboard/system-health";
import UserTable from "@/components/users/user-table";
import UserModal from "@/components/users/user-modal";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Plus, History, Download, Key } from "lucide-react";

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
        
        <main className="flex-1 p-6 overflow-auto">
          {/* Metrics Cards */}
          <MetricsCards data={systemStats} />

          {/* Main Content Area */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mt-8">
            {/* Recent Users */}
            <div className="lg:col-span-2">
              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle>Recent Users</CardTitle>
                    <Button 
                      variant="ghost" 
                      size="sm"
                      data-testid="button-view-all-users"
                    >
                      View All
                    </Button>
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

              {/* Quick Actions */}
              <Card>
                <CardHeader>
                  <CardTitle>Quick Actions</CardTitle>
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
                  <Button 
                    variant="secondary" 
                    className="w-full justify-start"
                    data-testid="button-generate-api-key"
                  >
                    <Key className="mr-2 h-4 w-4" />
                    Generate API Key
                  </Button>
                  <Button 
                    variant="secondary" 
                    className="w-full justify-start"
                    data-testid="button-view-audit-logs"
                  >
                    <History className="mr-2 h-4 w-4" />
                    View Audit Logs
                  </Button>
                  <Button 
                    variant="secondary" 
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

          {/* Recent Activity */}
          <Card className="mt-8">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>Recent Security Events</CardTitle>
                <Button variant="ghost" size="sm" data-testid="button-view-all-events">
                  View All Events
                </Button>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {auditEvents && auditEvents.length > 0 ? (
                auditEvents.slice(0, 3).map((event: any) => (
                  <div 
                    key={event.id} 
                    className="flex items-start space-x-4 p-4 bg-muted rounded-lg"
                    data-testid={`event-${event.id}`}
                  >
                    <div className="w-8 h-8 bg-blue-100 dark:bg-blue-900 rounded-full flex items-center justify-center flex-shrink-0">
                      <i className="fas fa-sign-in-alt text-blue-600 dark:text-blue-400 text-sm"></i>
                    </div>
                    <div className="flex-1">
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
                        <span data-testid={`event-status-${event.id}`}>
                          {event.success ? 'Success' : 'Failed'}
                        </span>
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  No security events found
                </div>
              )}
            </CardContent>
          </Card>
        </main>
      </div>

      <UserModal 
        open={userModalOpen} 
        onOpenChange={setUserModalOpen}
      />
    </div>
  );
}
