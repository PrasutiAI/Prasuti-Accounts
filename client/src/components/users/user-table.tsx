import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Eye, Edit, Ban, CheckCircle, XCircle } from "lucide-react";
import { cn } from "@/lib/utils";

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

interface UserTableProps {
  users: User[];
  showActions?: boolean;
  onEdit?: (user: User) => void;
  onDelete?: (userId: string) => void;
  onToggleStatus?: (userId: string, currentStatus: string) => void;
}

export default function UserTable({ 
  users, 
  showActions = false, 
  onEdit, 
  onDelete, 
  onToggleStatus 
}: UserTableProps) {
  
  const getInitials = (name: string) => {
    return name
      .split(' ')
      .map(n => n[0])
      .join('')
      .toUpperCase()
      .slice(0, 2);
  };

  const getStatusBadge = (status: string) => {
    const statusConfig = {
      active: { label: "Active", className: "status-active" },
      inactive: { label: "Inactive", className: "status-inactive" },
      pending: { label: "Pending", className: "status-pending" },
      blocked: { label: "Blocked", className: "status-blocked" },
    };

    const config = statusConfig[status as keyof typeof statusConfig] || statusConfig.inactive;
    
    return (
      <Badge className={cn("status-badge", config.className)}>
        {config.label}
      </Badge>
    );
  };

  const getRoleBadge = (role: string) => {
    const roleColors = {
      admin: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300",
      developer: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300",
      user: "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300",
      guest: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300",
    };

    const colorClass = roleColors[role as keyof typeof roleColors] || roleColors.user;

    return (
      <Badge variant="secondary" className={cn("text-xs", colorClass)}>
        {role.charAt(0).toUpperCase() + role.slice(1)}
      </Badge>
    );
  };

  const formatLastLogin = (lastLogin: string | null) => {
    if (!lastLogin) return "Never";
    
    const date = new Date(lastLogin);
    const now = new Date();
    const diffInHours = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60));
    
    if (diffInHours < 1) return "Just now";
    if (diffInHours < 24) return `${diffInHours} hours ago`;
    if (diffInHours < 48) return "1 day ago";
    return `${Math.floor(diffInHours / 24)} days ago`;
  };

  if (users.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        No users found
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>User</TableHead>
            <TableHead>Role</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>MFA</TableHead>
            <TableHead>Last Login</TableHead>
            {showActions && <TableHead>Actions</TableHead>}
          </TableRow>
        </TableHeader>
        <TableBody>
          {users.map((user) => (
            <TableRow key={user.id} data-testid={`user-row-${user.id}`}>
              <TableCell>
                <div className="flex items-center space-x-3">
                  <Avatar className="h-8 w-8">
                    <AvatarFallback className="bg-primary text-primary-foreground text-xs">
                      {getInitials(user.name)}
                    </AvatarFallback>
                  </Avatar>
                  <div>
                    <p className="font-medium text-foreground" data-testid={`user-name-${user.id}`}>
                      {user.name}
                    </p>
                    <p className="text-sm text-muted-foreground" data-testid={`user-email-${user.id}`}>
                      {user.email}
                    </p>
                  </div>
                </div>
              </TableCell>
              <TableCell data-testid={`user-role-${user.id}`}>
                {getRoleBadge(user.role)}
              </TableCell>
              <TableCell data-testid={`user-status-${user.id}`}>
                {getStatusBadge(user.status)}
              </TableCell>
              <TableCell data-testid={`user-mfa-${user.id}`}>
                {user.mfaEnabled ? (
                  <CheckCircle className="h-4 w-4 text-green-600" />
                ) : (
                  <XCircle className="h-4 w-4 text-red-500" />
                )}
              </TableCell>
              <TableCell className="text-muted-foreground" data-testid={`user-last-login-${user.id}`}>
                {formatLastLogin(user.lastLogin)}
              </TableCell>
              {showActions && (
                <TableCell>
                  <div className="flex items-center space-x-2">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8"
                      data-testid={`button-view-${user.id}`}
                    >
                      <Eye className="h-4 w-4" />
                    </Button>
                    {onEdit && (
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8"
                        onClick={() => onEdit(user)}
                        data-testid={`button-edit-${user.id}`}
                      >
                        <Edit className="h-4 w-4" />
                      </Button>
                    )}
                    {onToggleStatus && (
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8"
                        onClick={() => onToggleStatus(user.id, user.status)}
                        data-testid={`button-toggle-status-${user.id}`}
                      >
                        <Ban className={cn(
                          "h-4 w-4",
                          user.status === 'blocked' ? "text-green-600" : "text-red-500"
                        )} />
                      </Button>
                    )}
                  </div>
                </TableCell>
              )}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
