import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Menu, Search, Bell, User, LogOut, Settings } from "lucide-react";
import { Link } from "wouter";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ThemeToggle } from "@/components/ui/theme-toggle";
import { useAuth } from "@/hooks/use-auth";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";

interface HeaderProps {
  onSidebarToggle: () => void;
}

export default function Header({ onSidebarToggle }: HeaderProps) {
  const { user, logout } = useAuth();
  const [searchQuery, setSearchQuery] = useState("");
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: notifications } = useQuery<any[]>({
    queryKey: ['/api/audit/security-events'],
    select: (data: any[]) => data?.slice(0, 5) || [], // Get latest 5 events
  });

  const logoutMutation = useMutation({
    mutationFn: async () => {
      const refreshToken = localStorage.getItem('refreshToken');
      if (refreshToken) {
        await apiRequest('POST', '/api/auth/logout', { refreshToken });
      }
    },
    onSettled: () => {
      logout();
    },
  });

  const handleLogout = () => {
    logoutMutation.mutate();
  };

  const getInitials = (name: string) => {
    return name
      .split(' ')
      .map(n => n[0])
      .join('')
      .toUpperCase()
      .slice(0, 2);
  };

  const unreadNotifications = notifications?.filter((n: any) => !n.success)?.length || 0;

  return (
    <header className="bg-card/95 backdrop-blur-sm border-b border-border/50 px-4 md:px-6 py-4 shadow-lg sticky top-0 z-40">
      <div className="flex items-center justify-between">
        {/* Enhanced Left side */}
        <div className="flex items-center space-x-3 md:space-x-4">
          <Button 
            variant="ghost" 
            size="icon"
            onClick={onSidebarToggle}
            className="group transition-all duration-300 hover:bg-accent/80 hover:scale-105 rounded-xl"
            data-testid="button-sidebar-toggle"
            aria-label="Toggle sidebar"
          >
            <Menu className="h-5 w-5 text-muted-foreground group-hover:text-foreground transition-all duration-300 group-hover:rotate-180" />
          </Button>
          
          <div className="hidden sm:block">
            <h2 className="text-lg md:text-xl font-bold text-foreground transition-colors duration-200 bg-gradient-to-r from-foreground to-muted-foreground bg-clip-text">
              Identity Management Dashboard
            </h2>
            <p className="text-xs md:text-sm text-muted-foreground/80 font-medium">
              Monitor and manage authentication services
            </p>
          </div>
          
          {/* Enhanced Mobile title */}
          <div className="block sm:hidden">
            <h2 className="text-lg font-bold text-foreground">IDM Dashboard</h2>
          </div>
        </div>

        {/* Right side */}
        <div className="flex items-center space-x-2 md:space-x-4">
          {/* Enhanced Search */}
          <div className="relative hidden md:block group">
            <div className="absolute left-3 top-1/2 transform -translate-y-1/2 z-10">
              <Search className="h-4 w-4 text-muted-foreground group-focus-within:text-primary transition-colors duration-300" />
            </div>
            <Input
              type="text"
              placeholder="Search users, roles..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-48 lg:w-64 pl-10 pr-4 transition-all duration-300 focus:w-56 lg:focus:w-72 bg-background/50 border-border/60 focus:border-primary/50 focus:ring-primary/20 focus:bg-background rounded-xl hover:bg-background/80"
              data-testid="input-header-search"
            />
            {searchQuery && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setSearchQuery("")}
                className="absolute right-2 top-1/2 transform -translate-y-1/2 h-6 w-6 p-0 hover:bg-accent/60 rounded-full text-muted-foreground hover:text-foreground"
                aria-label="Clear search"
                data-testid="button-clear-search"
              >
                ✕
              </Button>
            )}
          </div>
          
          {/* Enhanced Mobile search button */}
          <Button 
            variant="ghost" 
            size="icon" 
            className="group md:hidden transition-all duration-300 hover:bg-accent/80 hover:scale-105 rounded-xl"
            data-testid="button-mobile-search"
            aria-label="Search"
          >
            <Search className="h-5 w-5 text-muted-foreground group-hover:text-foreground transition-colors duration-300" />
          </Button>

          {/* Enhanced Notifications */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button 
                variant="ghost" 
                size="icon" 
                className="group relative transition-all duration-300 hover:bg-accent/80 hover:scale-105 rounded-xl" 
                data-testid="button-notifications"
                aria-label={unreadNotifications > 0 ? `${unreadNotifications} new notifications` : "Notifications"}
              >
                <Bell className="h-5 w-5 text-muted-foreground group-hover:text-foreground transition-all duration-300" />
                {unreadNotifications > 0 && (
                  <Badge 
                    variant="destructive" 
                    className="absolute -top-1 -right-1 h-5 w-5 rounded-full p-0 text-xs flex items-center justify-center animate-pulse shadow-md"
                  >
                    {unreadNotifications}
                  </Badge>
                )}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-80 animate-scale-in">
              <DropdownMenuLabel className="text-base font-semibold">Recent Security Events</DropdownMenuLabel>
              <DropdownMenuSeparator />
              {notifications && notifications.length > 0 ? (
                notifications.map((event: any) => (
                  <DropdownMenuItem key={event.id} className="flex flex-col items-start space-y-1 p-3 hover:bg-accent/50 transition-colors duration-200">
                    <div className="flex items-center space-x-2 w-full">
                      <div className={cn(
                        "w-3 h-3 rounded-full flex-shrink-0 shadow-sm",
                        event.success ? "bg-green-500" : "bg-red-500"
                      )} />
                      <span className="font-medium text-sm flex-1">
                        {event.action === 'login' ? 'Login attempt' : event.action}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground ml-5">
                      {event.metadata?.email || 'System'} - {new Date(event.createdAt).toLocaleString()}
                    </p>
                  </DropdownMenuItem>
                ))
              ) : (
                <DropdownMenuItem disabled className="text-center py-4">
                  No recent events
                </DropdownMenuItem>
              )}
            </DropdownMenuContent>
          </DropdownMenu>

          {/* Theme Toggle */}
          <ThemeToggle />

          {/* Enhanced User Menu */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button 
                variant="ghost" 
                className="group flex items-center space-x-2 md:space-x-3 transition-all duration-300 hover:bg-accent/80 hover:scale-105 rounded-xl p-2" 
                data-testid="button-user-menu"
                aria-label="User menu"
              >
                <div className="relative">
                  <Avatar className="h-9 w-9 transition-all duration-300 group-hover:shadow-md ring-2 ring-transparent group-hover:ring-primary/20">
                    <AvatarFallback className="bg-gradient-to-br from-primary via-primary/90 to-primary/70 text-primary-foreground font-semibold text-sm shadow-sm">
                      {user ? getInitials(user.name) : 'U'}
                    </AvatarFallback>
                  </Avatar>
                  <div className="absolute -bottom-0.5 -right-0.5 w-3 h-3 bg-green-500 rounded-full border-2 border-background shadow-sm"></div>
                </div>
                <div className="text-left hidden sm:block">
                  <p className="text-sm font-semibold text-foreground transition-colors duration-200 group-hover:text-primary" data-testid="text-user-name">
                    {user?.name || 'User'}
                  </p>
                  <p className="text-xs text-muted-foreground/80 font-medium" data-testid="text-user-email">
                    {user?.email || 'user@example.com'}
                  </p>
                </div>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56 animate-scale-in">
              <DropdownMenuLabel className="text-base font-semibold">My Account</DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem data-testid="menu-profile" className="hover:bg-accent/50 transition-colors duration-200">
                <User className="mr-2 h-4 w-4" />
                Profile
              </DropdownMenuItem>
              <DropdownMenuItem 
                data-testid="menu-settings"
                className="hover:bg-accent/50 transition-colors duration-200"
                onSelect={() => window.location.href = '/settings'}
              >
                <Settings className="mr-2 h-4 w-4" />
                Settings
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem 
                onClick={handleLogout}
                data-testid="menu-logout"
                className="text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors duration-200"
              >
                <LogOut className="mr-2 h-4 w-4" />
                Sign Out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </header>
  );
}
