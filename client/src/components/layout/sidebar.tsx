import { Link, useLocation } from "wouter";
import { cn } from "@/lib/utils";
import { 
  Shield, 
  BarChart3, 
  Users, 
  UserCheck, 
  Key, 
  Smartphone, 
  Link as LinkIcon, 
  History, 
  Settings,
  HelpCircle
} from "lucide-react";
import { Button } from "@/components/ui/button";
import ProtectedComponent from "@/components/auth/ProtectedComponent";
import { usePermissions } from "@/hooks/use-permissions";

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
  currentPage?: string;
}

const navigation = [
  { 
    name: "Dashboard", 
    href: "/", 
    icon: BarChart3, 
    id: "dashboard",
    roles: ['admin', 'developer', 'user', 'guest'],
    permissions: [] // Everyone with access can see dashboard
  },
  { 
    name: "Users", 
    href: "/users", 
    icon: Users, 
    id: "users",
    roles: ['admin', 'developer'],
    permissions: ['users:read']
  },
  { 
    name: "Roles & Permissions", 
    href: "/roles", 
    icon: UserCheck, 
    id: "roles",
    roles: ['admin'],
    permissions: ['roles:read']
  },
  { 
    name: "API Keys", 
    href: "/api-keys", 
    icon: Key, 
    id: "api-keys",
    roles: ['admin', 'developer'],
    permissions: ['api-keys:read']
  },
  { 
    name: "MFA Settings", 
    href: "/mfa", 
    icon: Smartphone, 
    id: "mfa",
    roles: ['admin', 'developer', 'user'],
    permissions: ['settings:read']
  },
  { 
    name: "Audit Logs", 
    href: "/audit", 
    icon: History, 
    id: "audit",
    roles: ['admin', 'developer'],
    permissions: ['audit:read']
  },
  { 
    name: "System Settings", 
    href: "/settings", 
    icon: Settings, 
    id: "settings",
    roles: ['admin', 'developer', 'user'],
    permissions: ['settings:read']
  },
];

export default function Sidebar({ collapsed, currentPage = "dashboard" }: SidebarProps) {
  const [location] = useLocation();
  const { hasRole, hasAnyPermission } = usePermissions();

  return (
    <div className={cn(
      "bg-card border-r border-border transition-all duration-300 flex flex-col",
      collapsed ? "sidebar-collapsed" : "sidebar-expanded"
    )}>
      {/* Header */}
      <div className="p-6 border-b border-border">
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 bg-primary rounded-lg flex items-center justify-center">
            <Shield className="h-4 w-4 text-primary-foreground" />
          </div>
          {!collapsed && (
            <div className="sidebar-text">
              <h1 className="text-lg font-semibold text-foreground">Prasuti.AI</h1>
              <p className="text-xs text-muted-foreground">Identity Management</p>
            </div>
          )}
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4 space-y-2">
        {navigation.map((item) => {
          const isActive = 
            (item.href === "/" && (location === "/" || currentPage === "dashboard")) ||
            (item.href !== "/" && location.startsWith(item.href));
          
          return (
            <ProtectedComponent
              key={item.id}
              requiredRoles={item.roles}
              requiredPermissions={item.permissions.length > 0 ? item.permissions : undefined}
              hideOnError={true}
            >
              <Link href={item.href}>
                <Button
                  variant={isActive ? "secondary" : "ghost"}
                  className={cn(
                    "w-full justify-start",
                    isActive && "bg-accent text-accent-foreground font-medium"
                  )}
                  data-testid={`nav-${item.id}`}
                >
                  <item.icon className="h-5 w-5" />
                  {!collapsed && (
                    <span className="sidebar-text ml-3">{item.name}</span>
                  )}
                </Button>
              </Link>
            </ProtectedComponent>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="p-4 border-t border-border">
        <Link href="/docs">
          <Button
            variant="ghost"
            className="w-full justify-start"
            data-testid="nav-docs"
          >
            <HelpCircle className="h-5 w-5" />
            {!collapsed && (
              <span className="sidebar-text ml-3">API Docs</span>
            )}
          </Button>
        </Link>
      </div>
    </div>
  );
}
