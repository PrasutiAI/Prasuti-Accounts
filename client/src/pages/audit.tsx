import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import Sidebar from "@/components/layout/sidebar";
import Header from "@/components/layout/header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { History, Search, Shield, User, LogIn, LogOut, UserPlus, Settings as SettingsIcon } from "lucide-react";
import { format } from "date-fns";

const actionIcons = {
  login: LogIn,
  logout: LogOut,
  register: UserPlus,
  password_change: Shield,
  mfa_enable: Shield,
  mfa_disable: Shield,
  role_change: User,
  user_create: UserPlus,
  user_update: User,
  user_delete: User,
  key_rotation: Shield,
  api_key_create: Shield,
  api_key_revoke: Shield,
  settings: SettingsIcon,
};

export default function Audit() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [actionFilter, setActionFilter] = useState<string>("all");
  const [currentPage, setCurrentPage] = useState(1);

  const { data: auditLogs, isLoading } = useQuery({
    queryKey: ['/api/audit', { page: currentPage, limit: 50, action: actionFilter }],
  });

  const { data: auditStats } = useQuery({
    queryKey: ['/api/audit/stats'],
  });

  const filteredLogs = (auditLogs as any)?.data?.filter((log: any) => {
    const matchesSearch = 
      log.details?.email?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.action.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.ipAddress?.toLowerCase().includes(searchQuery.toLowerCase());
    
    const matchesAction = actionFilter === "all" || log.action === actionFilter;
    
    return matchesSearch && matchesAction;
  }) || [];

  const getActionBadgeVariant = (action: string, success: boolean) => {
    if (!success) return 'destructive';
    
    switch (action) {
      case 'login':
      case 'logout':
        return 'default';
      case 'register':
      case 'user_create':
        return 'default';
      case 'password_change':
      case 'mfa_enable':
      case 'key_rotation':
        return 'default';
      case 'user_delete':
      case 'mfa_disable':
      case 'api_key_revoke':
        return 'secondary';
      default:
        return 'outline';
    }
  };

  const getActionIcon = (action: string) => {
    const IconComponent = actionIcons[action as keyof typeof actionIcons] || History;
    return IconComponent;
  };

  const formatActionName = (action: string) => {
    return action.split('_').map(word => 
      word.charAt(0).toUpperCase() + word.slice(1)
    ).join(' ');
  };

  return (
    <div className="flex h-screen bg-background">
      <Sidebar 
        collapsed={sidebarCollapsed} 
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
        currentPage="audit"
      />
      
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header onSidebarToggle={() => setSidebarCollapsed(!sidebarCollapsed)} />
        
        <main className="flex-1 overflow-auto p-6">
          <div className="max-w-7xl mx-auto space-y-6">
            {/* Header */}
            <div>
              <h1 className="text-3xl font-bold text-foreground flex items-center gap-2" data-testid="text-page-title">
                <History className="w-8 h-8 text-primary" />
                Audit Logs
              </h1>
              <p className="text-muted-foreground mt-1">
                View system audit logs and security events
              </p>
            </div>

            {/* Stats Cards */}
            {auditStats && (auditStats as any).totalEvents !== undefined && (
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <Card>
                  <CardContent className="pt-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-muted-foreground">Total Events</p>
                        <p className="text-2xl font-bold">{(auditStats as any).totalEvents || 0}</p>
                      </div>
                      <History className="w-8 h-8 text-muted-foreground" />
                    </div>
                  </CardContent>
                </Card>
                
                <Card>
                  <CardContent className="pt-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-muted-foreground">Failed Logins</p>
                        <p className="text-2xl font-bold text-destructive">{(auditStats as any).failedLogins || 0}</p>
                      </div>
                      <Shield className="w-8 h-8 text-destructive" />
                    </div>
                  </CardContent>
                </Card>
                
                <Card>
                  <CardContent className="pt-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-muted-foreground">Today's Events</p>
                        <p className="text-2xl font-bold">{(auditStats as any).todayEvents || 0}</p>
                      </div>
                      <History className="w-8 h-8 text-muted-foreground" />
                    </div>
                  </CardContent>
                </Card>
                
                <Card>
                  <CardContent className="pt-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-muted-foreground">Active Users</p>
                        <p className="text-2xl font-bold">{(auditStats as any).activeUsers || 0}</p>
                      </div>
                      <User className="w-8 h-8 text-muted-foreground" />
                    </div>
                  </CardContent>
                </Card>
              </div>
            )}

            {/* Filters */}
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center space-x-4">
                  <div className="relative flex-1">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground w-4 h-4" />
                    <Input
                      placeholder="Search by email, action, or IP address..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="pl-10"
                      data-testid="input-search"
                    />
                  </div>
                  
                  <Select value={actionFilter} onValueChange={setActionFilter}>
                    <SelectTrigger className="w-48" data-testid="select-action-filter">
                      <SelectValue placeholder="Filter by action" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Actions</SelectItem>
                      <SelectItem value="login">Login</SelectItem>
                      <SelectItem value="logout">Logout</SelectItem>
                      <SelectItem value="register">Register</SelectItem>
                      <SelectItem value="password_change">Password Change</SelectItem>
                      <SelectItem value="mfa_enable">MFA Enable</SelectItem>
                      <SelectItem value="mfa_disable">MFA Disable</SelectItem>
                      <SelectItem value="user_create">User Create</SelectItem>
                      <SelectItem value="user_update">User Update</SelectItem>
                      <SelectItem value="user_delete">User Delete</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </CardContent>
            </Card>

            {/* Audit Logs Table */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <History className="w-5 h-5" />
                  Recent Activity ({filteredLogs.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                {isLoading ? (
                  <div className="flex items-center justify-center py-8">
                    <div className="text-muted-foreground">Loading audit logs...</div>
                  </div>
                ) : filteredLogs.length === 0 ? (
                  <div className="flex items-center justify-center py-8">
                    <div className="text-muted-foreground">
                      {searchQuery || actionFilter !== "all" ? 'No logs match your filters' : 'No audit logs found'}
                    </div>
                  </div>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Action</TableHead>
                        <TableHead>User</TableHead>
                        <TableHead>IP Address</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Details</TableHead>
                        <TableHead>Timestamp</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {filteredLogs.map((log: any) => {
                        const IconComponent = getActionIcon(log.action);
                        const success = log.details?.success !== false;
                        
                        return (
                          <TableRow key={log.id} data-testid={`row-audit-log-${log.id}`}>
                            <TableCell>
                              <div className="flex items-center gap-2">
                                <IconComponent className="w-4 h-4" />
                                <Badge variant={getActionBadgeVariant(log.action, success)}>
                                  {formatActionName(log.action)}
                                </Badge>
                              </div>
                            </TableCell>
                            <TableCell>
                              <div>
                                {log.details?.email || log.userId || 'System'}
                              </div>
                            </TableCell>
                            <TableCell>
                              <code className="text-sm">{log.ipAddress || 'N/A'}</code>
                            </TableCell>
                            <TableCell>
                              <Badge variant={success ? "default" : "destructive"}>
                                {success ? "Success" : "Failed"}
                              </Badge>
                            </TableCell>
                            <TableCell className="max-w-xs">
                              <div className="truncate text-sm text-muted-foreground">
                                {log.details?.reason || log.details?.message || 'No additional details'}
                              </div>
                            </TableCell>
                            <TableCell>
                              <div className="text-sm">
                                {format(new Date(log.createdAt), 'MMM d, yyyy HH:mm:ss')}
                              </div>
                            </TableCell>
                          </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>
          </div>
        </main>
      </div>
    </div>
  );
}