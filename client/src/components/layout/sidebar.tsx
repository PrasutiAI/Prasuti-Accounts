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
      "bg-card border-r border-border transition-all duration-300 flex flex-col shadow-sm",
      collapsed ? "sidebar-collapsed" : "sidebar-expanded"
    )}>
      {/* Enhanced Header */}
      <div className="p-6 border-b border-border bg-gradient-enhanced">
        <div className="flex items-center space-x-3">
          <div className="relative group">
            <div className="w-10 h-10 bg-gradient-to-br from-primary via-primary/90 to-primary/70 rounded-xl flex items-center justify-center shadow-md transition-all duration-300 hover:scale-110 hover:shadow-lg hover:rotate-3">
              <Shield className="h-5 w-5 text-primary-foreground drop-shadow-sm" />
            </div>
            <div className="absolute -inset-0.5 bg-gradient-to-br from-primary/20 to-transparent rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300 -z-10"></div>
          </div>
          {!collapsed && (
            <div className="sidebar-text transition-all duration-300 transform">
              <h1 className="text-lg font-bold text-foreground tracking-tight">Prasuti.AI</h1>
              <p className="text-xs text-muted-foreground font-medium">Identity Management Hub</p>
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
                    "group w-full justify-start relative transition-all duration-300 hover-lift rounded-lg",
                    isActive && "bg-gradient-to-r from-primary/15 via-primary/10 to-primary/5 text-primary font-semibold shadow-md border border-primary/30 hover:from-primary/20 hover:via-primary/15 hover:to-primary/10",
                    !isActive && "hover:bg-accent/60 hover:text-accent-foreground hover:translate-x-2 hover:shadow-md"
                  )}
                  data-testid={`nav-${item.id}`}
                >
                  <div className={cn(
                    "flex items-center justify-center w-8 h-8 rounded-lg transition-all duration-300",
                    isActive ? "bg-primary/10 shadow-sm" : "group-hover:bg-accent/40"
                  )}>
                    <item.icon className={cn(
                      "h-4 w-4 transition-all duration-300",
                      isActive ? "text-primary drop-shadow-sm" : "text-muted-foreground group-hover:text-foreground group-hover:scale-110"
                    )} />
                  </div>
                  {!collapsed && (
                    <span className="sidebar-text ml-3 transition-all duration-300 font-medium">{item.name}</span>
                  )}
                  {isActive && !collapsed && (
                    <div className="absolute right-3 w-2 h-2 bg-primary rounded-full animate-pulse shadow-sm" />
                  )}
                  {!collapsed && (
                    <div className={cn(
                      "absolute left-0 w-1 h-8 bg-primary rounded-r-full transition-all duration-300 opacity-0",
                      isActive && "opacity-100"
                    )} />
                  )}
                </Button>
              </Link>
            </ProtectedComponent>
          );
        })}
      </nav>

      {/* Enhanced Footer */}
      <div className="p-4 border-t border-border/60 bg-gradient-to-b from-muted/20 to-muted/40">
        <Link href="/docs">
          <Button
            variant="ghost"
            className="group w-full justify-start transition-all duration-300 hover-lift rounded-lg hover:bg-accent/50 hover:translate-x-2"
            data-testid="nav-docs"
          >
            <div className="flex items-center justify-center w-8 h-8 rounded-lg transition-all duration-300 group-hover:bg-accent/40">
              <HelpCircle className="h-4 w-4 text-muted-foreground group-hover:text-foreground group-hover:scale-110 transition-all duration-300" />
            </div>
            {!collapsed && (
              <span className="sidebar-text ml-3 transition-all duration-300 text-sm font-medium text-muted-foreground group-hover:text-foreground">API Docs</span>
            )}
          </Button>
        </Link>
        {!collapsed && (
          <div className="mt-3 px-3 py-2 text-xs text-muted-foreground/70 animate-fade-in">
            <p className="font-medium">v2.0.0</p>
            <p>Enterprise Ready</p>
          </div>
        )}
      </div>
    </div>
  );
}
