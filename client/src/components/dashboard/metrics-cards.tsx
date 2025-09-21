import { Card, CardContent } from "@/components/ui/card";
import { Users, Wifi, Key, AlertTriangle, TrendingUp, TrendingDown, Minus } from "lucide-react";

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

interface MetricsCardsProps {
  data?: MetricsData;
}

export default function MetricsCards({ data }: MetricsCardsProps) {
  // Mock calculation for failed logins (in production this would come from API)
  const mockFailedLogins = Math.floor(Math.random() * 50) + 10;

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
      {/* Total Users */}
      <Card>
        <CardContent className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-muted-foreground text-sm">Total Users</p>
              <p className="text-2xl font-semibold text-foreground" data-testid="metric-total-users">
                {data?.system?.totalUsers?.toLocaleString() || '0'}
              </p>
            </div>
            <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center">
              <Users className="h-6 w-6 text-primary" />
            </div>
          </div>
          <div className="mt-4 flex items-center text-sm">
            <TrendingUp className="h-4 w-4 text-green-600 mr-1" />
            <span className="text-green-600">12%</span>
            <span className="text-muted-foreground ml-2">vs last month</span>
          </div>
        </CardContent>
      </Card>

      {/* Active Sessions */}
      <Card>
        <CardContent className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-muted-foreground text-sm">Active Users</p>
              <p className="text-2xl font-semibold text-foreground" data-testid="metric-active-users">
                {data?.system?.activeUsers?.toLocaleString() || '0'}
              </p>
            </div>
            <div className="w-12 h-12 bg-green-100 dark:bg-green-900 rounded-lg flex items-center justify-center">
              <Wifi className="h-6 w-6 text-green-600" />
            </div>
          </div>
          <div className="mt-4 flex items-center text-sm">
            <TrendingUp className="h-4 w-4 text-green-600 mr-1" />
            <span className="text-green-600">8%</span>
            <span className="text-muted-foreground ml-2">vs last hour</span>
          </div>
        </CardContent>
      </Card>

      {/* API Keys */}
      <Card>
        <CardContent className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-muted-foreground text-sm">Active Keys</p>
              <p className="text-2xl font-semibold text-foreground" data-testid="metric-api-keys">
                {data?.system?.activeKeys || '0'}
              </p>
            </div>
            <div className="w-12 h-12 bg-yellow-100 dark:bg-yellow-900 rounded-lg flex items-center justify-center">
              <Key className="h-6 w-6 text-yellow-600" />
            </div>
          </div>
          <div className="mt-4 flex items-center text-sm">
            <Minus className="h-4 w-4 text-yellow-600 mr-1" />
            <span className="text-yellow-600">2%</span>
            <span className="text-muted-foreground ml-2">vs last week</span>
          </div>
        </CardContent>
      </Card>

      {/* Failed Logins */}
      <Card>
        <CardContent className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-muted-foreground text-sm">Failed Logins (24h)</p>
              <p className="text-2xl font-semibold text-foreground" data-testid="metric-failed-logins">
                {mockFailedLogins}
              </p>
            </div>
            <div className="w-12 h-12 bg-red-100 dark:bg-red-900 rounded-lg flex items-center justify-center">
              <AlertTriangle className="h-6 w-6 text-red-600" />
            </div>
          </div>
          <div className="mt-4 flex items-center text-sm">
            <TrendingDown className="h-4 w-4 text-green-600 mr-1" />
            <span className="text-green-600">15%</span>
            <span className="text-muted-foreground ml-2">vs yesterday</span>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
