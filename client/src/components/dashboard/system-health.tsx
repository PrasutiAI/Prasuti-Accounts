import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { RefreshCw } from "lucide-react";

interface SystemHealthProps {
  className?: string;
}

export default function SystemHealth({ className }: SystemHealthProps) {
  const { data: keys } = useQuery({
    queryKey: ['/api/admin/keys'],
    // For now, mock the JWT keys data since we don't have the endpoint
    queryFn: () => Promise.resolve([
      {
        kid: 'key-2025-01',
        isActive: true,
        expiresAt: new Date(Date.now() + 89 * 24 * 60 * 60 * 1000).toISOString(),
        createdAt: new Date().toISOString(),
      },
      {
        kid: 'key-2024-12', 
        isActive: false,
        expiresAt: new Date(Date.now() + 12 * 24 * 60 * 60 * 1000).toISOString(),
        createdAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
      }
    ]),
  });

  const handleRotateKeys = async () => {
    // This would call the key rotation endpoint
    console.log('Rotating keys...');
  };

  // Mock health data
  const healthData = [
    { name: "Database", status: "healthy", uptime: "99.9%" },
    { name: "Redis Cache", status: "healthy", uptime: "100%" },
    { name: "JWT Service", status: "healthy", uptime: "100%" },
    { name: "Email Service", status: "warning", uptime: "98.1%" },
  ];

  const getHealthColor = (status: string) => {
    switch (status) {
      case 'healthy':
        return 'bg-green-500';
      case 'warning':
        return 'bg-yellow-500';
      case 'error':
        return 'bg-red-500';
      default:
        return 'bg-gray-500';
    }
  };

  return (
    <div className="space-y-6">
      {/* System Health */}
      <Card>
        <CardHeader>
          <CardTitle>System Health</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {healthData.map((service) => (
            <div key={service.name} className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <div className={`w-3 h-3 rounded-full ${getHealthColor(service.status)}`} />
                <span className="text-sm text-foreground" data-testid={`health-${service.name.toLowerCase().replace(' ', '-')}`}>
                  {service.name}
                </span>
              </div>
              <span className="text-sm text-muted-foreground">
                {service.uptime}
              </span>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* JWT Keys Status */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>JWT Keys</CardTitle>
            <Button 
              variant="outline" 
              size="sm"
              onClick={handleRotateKeys}
              data-testid="button-rotate-keys"
            >
              <RefreshCw className="h-4 w-4 mr-2" />
              Rotate
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          {keys?.map((key: any) => (
            <div key={key.kid} className="flex items-center justify-between p-3 bg-muted rounded-lg">
              <div>
                <p className="text-sm font-medium text-foreground font-mono" data-testid={`key-${key.kid}`}>
                  {key.kid}
                </p>
                <p className="text-xs text-muted-foreground">
                  {key.isActive ? 'Active' : 'Deprecated'} • 
                  {key.isActive 
                    ? ` Expires in ${Math.ceil((new Date(key.expiresAt).getTime() - Date.now()) / (1000 * 60 * 60 * 24))} days`
                    : ` ${Math.ceil((new Date(key.expiresAt).getTime() - Date.now()) / (1000 * 60 * 60 * 24))} days left`
                  }
                </p>
              </div>
              <Badge 
                variant={key.isActive ? "default" : "secondary"}
                className={key.isActive ? "status-active" : "status-pending"}
              >
                {key.isActive ? "Active" : "Deprecated"}
              </Badge>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
