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

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
  currentPage?: string;
}

const navigation = [
  { name: "Dashboard", href: "/", icon: BarChart3, id: "dashboard" },
  { name: "Users", href: "/users", icon: Users, id: "users" },
  { name: "Roles & Permissions", href: "/roles", icon: UserCheck, id: "roles" },
  { name: "API Keys", href: "/api-keys", icon: Key, id: "api-keys" },
  { name: "MFA Settings", href: "/mfa", icon: Smartphone, id: "mfa" },
  { name: "Social Login", href: "/social", icon: LinkIcon, id: "social" },
  { name: "Audit Logs", href: "/audit", icon: History, id: "audit" },
  { name: "System Settings", href: "/settings", icon: Settings, id: "settings" },
];

export default function Sidebar({ collapsed, currentPage = "dashboard" }: SidebarProps) {
  const [location] = useLocation();

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
            <Link key={item.id} href={item.href}>
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
