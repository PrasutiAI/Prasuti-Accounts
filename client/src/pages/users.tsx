import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import Sidebar from "@/components/layout/sidebar";
import Header from "@/components/layout/header";
import UserTable from "@/components/users/user-table";
import UserModal from "@/components/users/user-modal";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { Plus, Search, Users as UsersIcon, UserPlus, UserX, Shield } from "lucide-react";

export default function Users() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [userModalOpen, setUserModalOpen] = useState(false);
  const [selectedUser, setSelectedUser] = useState<any>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: usersData, isLoading } = useQuery({
    queryKey: ['/api/users', { page: currentPage, limit: 20 }],
  });

  const { data: userStats } = useQuery({
    queryKey: ['/api/admin/stats'],
  });

  const deleteUserMutation = useMutation({
    mutationFn: async (userId: string) => {
      const response = await apiRequest('DELETE', `/api/users/${userId}`);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/users'] });
      queryClient.invalidateQueries({ queryKey: ['/api/admin/stats'] });
      toast({
        title: "User deleted",
        description: "User has been successfully deleted",
      });
    },
    onError: (error: any) => {
      toast({
        title: "Failed to delete user",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const toggleUserStatusMutation = useMutation({
    mutationFn: async ({ userId, status }: { userId: string; status: string }) => {
      const response = await apiRequest('PATCH', `/api/users/${userId}`, { status });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/users'] });
      queryClient.invalidateQueries({ queryKey: ['/api/admin/stats'] });
      toast({
        title: "User status updated",
        description: "User status has been successfully updated",
      });
    },
    onError: (error: any) => {
      toast({
        title: "Failed to update user status",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const handleEditUser = (user: any) => {
    setSelectedUser(user);
    setUserModalOpen(true);
  };

  const handleDeleteUser = (userId: string) => {
    if (confirm("Are you sure you want to delete this user? This action cannot be undone.")) {
      deleteUserMutation.mutate(userId);
    }
  };

  const handleToggleUserStatus = (userId: string, currentStatus: string) => {
    const newStatus = currentStatus === 'active' ? 'blocked' : 'active';
    toggleUserStatusMutation.mutate({ userId, status: newStatus });
  };

  const filteredUsers = usersData?.users?.filter((user: any) =>
    user.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
    user.name.toLowerCase().includes(searchQuery.toLowerCase())
  ) || [];

  return (
    <div className="min-h-screen flex bg-background">
      <Sidebar 
        collapsed={sidebarCollapsed} 
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
        currentPage="users"
      />
      
      <div className="flex-1 flex flex-col">
        <Header onSidebarToggle={() => setSidebarCollapsed(!sidebarCollapsed)} />
        
        <main className="flex-1 p-6 overflow-auto">
          {/* Page Header */}
          <div className="flex items-center justify-between mb-6">
            <div>
              <h1 className="text-2xl font-semibold text-foreground">User Management</h1>
              <p className="text-muted-foreground">Manage users, roles, and permissions</p>
            </div>
            <Button 
              onClick={() => {
                setSelectedUser(null);
                setUserModalOpen(true);
              }}
              data-testid="button-create-user"
            >
              <Plus className="mr-2 h-4 w-4" />
              Create User
            </Button>
          </div>

          {/* Stats Cards */}
          {userStats && (
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-muted-foreground text-sm">Total Users</p>
                      <p className="text-2xl font-semibold text-foreground" data-testid="stat-total-users">
                        {userStats.users.totalUsers}
                      </p>
                    </div>
                    <UsersIcon className="h-8 w-8 text-primary" />
                  </div>
                </CardContent>
              </Card>
              
              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-muted-foreground text-sm">Active Users</p>
                      <p className="text-2xl font-semibold text-foreground" data-testid="stat-active-users">
                        {userStats.users.activeUsers}
                      </p>
                    </div>
                    <UserPlus className="h-8 w-8 text-green-500" />
                  </div>
                </CardContent>
              </Card>
              
              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-muted-foreground text-sm">Pending Users</p>
                      <p className="text-2xl font-semibold text-foreground" data-testid="stat-pending-users">
                        {userStats.users.pendingUsers}
                      </p>
                    </div>
                    <UserX className="h-8 w-8 text-yellow-500" />
                  </div>
                </CardContent>
              </Card>
              
              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-muted-foreground text-sm">MFA Enabled</p>
                      <p className="text-2xl font-semibold text-foreground" data-testid="stat-mfa-enabled">
                        {userStats.users.mfaEnabledUsers}
                      </p>
                    </div>
                    <Shield className="h-8 w-8 text-blue-500" />
                  </div>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Filters and Search */}
          <Card className="mb-6">
            <CardContent className="p-6">
              <div className="flex items-center space-x-4">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Search users by email or name..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="pl-10"
                    data-testid="input-search-users"
                  />
                </div>
                <div className="flex items-center space-x-2">
                  <Badge variant="secondary">
                    {filteredUsers.length} users found
                  </Badge>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Users Table */}
          <Card>
            <CardHeader>
              <CardTitle>All Users</CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="flex items-center justify-center py-8">
                  <div className="text-muted-foreground">Loading users...</div>
                </div>
              ) : (
                <UserTable 
                  users={filteredUsers}
                  showActions={true}
                  onEdit={handleEditUser}
                  onDelete={handleDeleteUser}
                  onToggleStatus={handleToggleUserStatus}
                />
              )}
            </CardContent>
          </Card>

          {/* Pagination */}
          {usersData && usersData.pages > 1 && (
            <div className="flex items-center justify-center space-x-2 mt-6">
              <Button
                variant="outline"
                disabled={currentPage === 1}
                onClick={() => setCurrentPage(currentPage - 1)}
                data-testid="button-previous-page"
              >
                Previous
              </Button>
              <span className="text-sm text-muted-foreground">
                Page {currentPage} of {usersData.pages}
              </span>
              <Button
                variant="outline"
                disabled={currentPage === usersData.pages}
                onClick={() => setCurrentPage(currentPage + 1)}
                data-testid="button-next-page"
              >
                Next
              </Button>
            </div>
          )}
        </main>
      </div>

      <UserModal 
        open={userModalOpen} 
        onOpenChange={setUserModalOpen}
        user={selectedUser}
        onSuccess={() => {
          queryClient.invalidateQueries({ queryKey: ['/api/users'] });
          queryClient.invalidateQueries({ queryKey: ['/api/admin/stats'] });
        }}
      />
    </div>
  );
}
