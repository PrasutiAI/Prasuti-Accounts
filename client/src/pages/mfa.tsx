import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import Sidebar from "@/components/layout/sidebar";
import Header from "@/components/layout/header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/use-auth";
import { apiRequest } from "@/lib/queryClient";
import { Smartphone, Shield, QrCode, Key, CheckCircle, AlertCircle } from "lucide-react";

export default function MFA() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [verificationCode, setVerificationCode] = useState("");
  const [showQR, setShowQR] = useState(false);
  const { toast } = useToast();
  const { user } = useAuth();
  const queryClient = useQueryClient();

  const { data: mfaStatus, isLoading } = useQuery({
    queryKey: ['/api/mfa/status'],
  });

  const { data: qrCode } = useQuery({
    queryKey: ['/api/mfa/qr'],
    enabled: showQR && !(mfaStatus as any)?.enabled,
  });

  const enableMfaMutation = useMutation({
    mutationFn: async (code: string) => {
      const response = await apiRequest('POST', '/api/mfa/enable', { mfaCode: code });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/mfa/status'] });
      toast({
        title: "MFA enabled",
        description: "Multi-factor authentication has been successfully enabled",
      });
      setVerificationCode("");
      setShowQR(false);
    },
    onError: (error: any) => {
      toast({
        title: "Failed to enable MFA",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const disableMfaMutation = useMutation({
    mutationFn: async (code: string) => {
      const response = await apiRequest('POST', '/api/mfa/disable', { mfaCode: code });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/mfa/status'] });
      toast({
        title: "MFA disabled",
        description: "Multi-factor authentication has been disabled",
      });
      setVerificationCode("");
    },
    onError: (error: any) => {
      toast({
        title: "Failed to disable MFA",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const generateBackupCodesMutation = useMutation({
    mutationFn: async () => {
      const response = await apiRequest('POST', '/api/mfa/backup-codes');
      return response.json();
    },
    onSuccess: (data) => {
      // Show backup codes in a modal or download them
      toast({
        title: "Backup codes generated",
        description: "Your backup codes have been generated. Please save them securely.",
      });
    },
    onError: (error: any) => {
      toast({
        title: "Failed to generate backup codes",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const handleEnableMFA = () => {
    if (!verificationCode) {
      toast({
        title: "Verification required",
        description: "Please enter the 6-digit code from your authenticator app",
        variant: "destructive",
      });
      return;
    }
    enableMfaMutation.mutate(verificationCode);
  };

  const handleDisableMFA = () => {
    if (!verificationCode) {
      toast({
        title: "Verification required",
        description: "Please enter the 6-digit code from your authenticator app",
        variant: "destructive",
      });
      return;
    }
    disableMfaMutation.mutate(verificationCode);
  };

  return (
    <div className="flex h-screen bg-background">
      <Sidebar 
        collapsed={sidebarCollapsed} 
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
        currentPage="mfa"
      />
      
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header onSidebarToggle={() => setSidebarCollapsed(!sidebarCollapsed)} />
        
        <main className="flex-1 overflow-auto p-6">
          <div className="max-w-4xl mx-auto space-y-6">
            {/* Header */}
            <div>
              <h1 className="text-3xl font-bold text-foreground flex items-center gap-2" data-testid="text-page-title">
                <Smartphone className="w-8 h-8 text-primary" />
                Multi-Factor Authentication
              </h1>
              <p className="text-muted-foreground mt-1">
                Enhance your account security with multi-factor authentication
              </p>
            </div>

            {/* Current Status */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="w-5 h-5" />
                  Current Status
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    {(mfaStatus as any)?.enabled ? (
                      <CheckCircle className="w-6 h-6 text-green-500" />
                    ) : (
                      <AlertCircle className="w-6 h-6 text-yellow-500" />
                    )}
                    <div>
                      <p className="font-medium">
                        {(mfaStatus as any)?.enabled ? "MFA is enabled" : "MFA is disabled"}
                      </p>
                      <p className="text-sm text-muted-foreground">
                        {(mfaStatus as any)?.enabled 
                          ? "Your account is protected with multi-factor authentication"
                          : "Enable MFA to add an extra layer of security to your account"
                        }
                      </p>
                    </div>
                  </div>
                  <Badge variant={(mfaStatus as any)?.enabled ? "default" : "secondary"}>
                    {(mfaStatus as any)?.enabled ? "Enabled" : "Disabled"}
                  </Badge>
                </div>
              </CardContent>
            </Card>

            {/* Setup MFA */}
            {!(mfaStatus as any)?.enabled ? (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <QrCode className="w-5 h-5" />
                    Enable MFA
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <p className="text-sm text-muted-foreground">
                      1. Install an authenticator app like Google Authenticator, Authy, or 1Password
                    </p>
                    <p className="text-sm text-muted-foreground">
                      2. Scan the QR code below or enter the setup key manually
                    </p>
                    <p className="text-sm text-muted-foreground">
                      3. Enter the 6-digit verification code from your app
                    </p>
                  </div>

                  {!showQR ? (
                    <Button 
                      onClick={() => setShowQR(true)}
                      data-testid="button-show-qr"
                    >
                      <QrCode className="w-4 h-4 mr-2" />
                      Show QR Code
                    </Button>
                  ) : (
                    <div className="space-y-4">
                      {qrCode && (qrCode as any).qrCode && (
                        <div className="flex justify-center">
                          <img 
                            src={(qrCode as any).qrCode} 
                            alt="MFA QR Code" 
                            className="border rounded-lg"
                            data-testid="img-qr-code"
                          />
                        </div>
                      )}
                      
                      <div className="space-y-2">
                        <Label htmlFor="verification-code">Verification Code</Label>
                        <Input
                          id="verification-code"
                          placeholder="Enter 6-digit code"
                          value={verificationCode}
                          onChange={(e) => setVerificationCode(e.target.value)}
                          maxLength={6}
                          data-testid="input-verification-code"
                        />
                      </div>

                      <Button 
                        onClick={handleEnableMFA}
                        disabled={enableMfaMutation.isPending || verificationCode.length !== 6}
                        data-testid="button-enable-mfa"
                      >
                        {enableMfaMutation.isPending ? "Enabling..." : "Enable MFA"}
                      </Button>
                    </div>
                  )}
                </CardContent>
              </Card>
            ) : (
              /* MFA Management */
              <div className="space-y-6">
                {/* Disable MFA */}
                <Card>
                  <CardHeader>
                    <CardTitle className="text-destructive">Disable MFA</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <p className="text-sm text-muted-foreground">
                      Disabling MFA will make your account less secure. You'll need to enter a verification code to confirm.
                    </p>

                    <div className="space-y-2">
                      <Label htmlFor="disable-verification-code">Verification Code</Label>
                      <Input
                        id="disable-verification-code"
                        placeholder="Enter 6-digit code"
                        value={verificationCode}
                        onChange={(e) => setVerificationCode(e.target.value)}
                        maxLength={6}
                        data-testid="input-disable-verification-code"
                      />
                    </div>

                    <Button 
                      variant="destructive"
                      onClick={handleDisableMFA}
                      disabled={disableMfaMutation.isPending || verificationCode.length !== 6}
                      data-testid="button-disable-mfa"
                    >
                      {disableMfaMutation.isPending ? "Disabling..." : "Disable MFA"}
                    </Button>
                  </CardContent>
                </Card>

                {/* Backup Codes */}
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Key className="w-5 h-5" />
                      Backup Codes
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <p className="text-sm text-muted-foreground">
                      Generate backup codes that can be used to access your account if you lose your authenticator device.
                    </p>

                    <Button 
                      variant="outline"
                      onClick={() => generateBackupCodesMutation.mutate()}
                      disabled={generateBackupCodesMutation.isPending}
                      data-testid="button-generate-backup-codes"
                    >
                      {generateBackupCodesMutation.isPending ? "Generating..." : "Generate New Backup Codes"}
                    </Button>
                  </CardContent>
                </Card>
              </div>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}