import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useAuth } from "@/hooks/use-auth";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { User, ShieldCheck, Key, Trash2, Camera, CheckCircle, AlertTriangle, Copy } from "lucide-react";

// Form schemas
const profileSchema = z.object({
  name: z.string().min(1, "Name is required"),
  email: z.string().email("Please enter a valid email address"),
});

const passwordSchema = z.object({
  currentPassword: z.string().min(1, "Current password is required"),
  newPassword: z.string().min(8, "Password must be at least 8 characters long"),
  confirmPassword: z.string().min(1, "Please confirm your password"),
}).refine((data) => data.newPassword === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
});

const deleteAccountSchema = z.object({
  currentPassword: z.string().min(1, "Password is required to delete account"),
  confirmText: z.literal("DELETE").or(z.string().refine((val) => val === "DELETE", {
    message: "Please type DELETE to confirm",
  })),
});

type ProfileFormData = z.infer<typeof profileSchema>;
type PasswordFormData = z.infer<typeof passwordSchema>;
type DeleteAccountFormData = z.infer<typeof deleteAccountSchema>;

export default function Settings() {
  const { user, logout } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [showMfaSetup, setShowMfaSetup] = useState(false);
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);

  // Form instances
  const profileForm = useForm<ProfileFormData>({
    resolver: zodResolver(profileSchema),
    defaultValues: {
      name: user?.name || "",
      email: user?.email || "",
    },
  });

  const passwordForm = useForm<PasswordFormData>({
    resolver: zodResolver(passwordSchema),
    defaultValues: {
      currentPassword: "",
      newPassword: "",
      confirmPassword: "",
    },
  });

  const deleteAccountForm = useForm<DeleteAccountFormData>({
    resolver: zodResolver(deleteAccountSchema),
    defaultValues: {
      currentPassword: "",
      confirmText: "" as any, // Allow empty string initially, validation enforces "DELETE"
    },
  });

  // Query MFA status
  const { data: mfaStatus, isLoading: mfaLoading } = useQuery<{enabled: boolean; backupCodesCount: number}>({
    queryKey: ['/api/mfa/status'],
  });

  // Query MFA setup data when needed
  const { data: mfaSetupData, refetch: refetchMfaSetup } = useQuery<{secret: string; qrCode: string; backupCodes: string[]}>({
    queryKey: ['/api/mfa/setup'],
    enabled: showMfaSetup && !mfaStatus?.enabled,
  });

  // Profile update mutation
  const updateProfileMutation = useMutation({
    mutationFn: async (data: ProfileFormData) => {
      const response = await apiRequest('PATCH', `/api/users/${user?.id}`, data);
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "Profile updated",
        description: "Your profile has been updated successfully.",
      });
      queryClient.invalidateQueries({ queryKey: ['/api/users'] });
    },
    onError: (error: Error) => {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  // Password change mutation
  const changePasswordMutation = useMutation({
    mutationFn: async (data: PasswordFormData) => {
      const response = await apiRequest('POST', '/api/auth/change-password', {
        currentPassword: data.currentPassword,
        newPassword: data.newPassword,
      });
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "Password changed",
        description: "Your password has been changed successfully.",
      });
      passwordForm.reset();
    },
    onError: (error: Error) => {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  // MFA enable mutation
  const enableMfaMutation = useMutation({
    mutationFn: async (mfaCode: string) => {
      const response = await apiRequest('POST', '/api/mfa/enable', { mfaCode });
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "MFA enabled",
        description: "Multi-factor authentication has been enabled.",
      });
      setShowMfaSetup(false);
      queryClient.invalidateQueries({ queryKey: ['/api/mfa/status'] });
    },
    onError: (error: Error) => {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  // MFA disable mutation
  const disableMfaMutation = useMutation({
    mutationFn: async (mfaCode: string) => {
      const response = await apiRequest('POST', '/api/mfa/disable', { mfaCode });
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "MFA disabled",
        description: "Multi-factor authentication has been disabled.",
      });
      queryClient.invalidateQueries({ queryKey: ['/api/mfa/status'] });
    },
    onError: (error: Error) => {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  // Account deletion mutation
  const deleteAccountMutation = useMutation({
    mutationFn: async (data: DeleteAccountFormData) => {
      const response = await apiRequest('DELETE', '/api/auth/account', {
        currentPassword: data.currentPassword,
      });
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "Account deleted",
        description: "Your account has been deleted successfully.",
      });
      logout();
    },
    onError: (error: Error) => {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const handleProfileSubmit = (data: ProfileFormData) => {
    updateProfileMutation.mutate(data);
  };

  const handlePasswordSubmit = (data: PasswordFormData) => {
    changePasswordMutation.mutate(data);
  };

  const handleDeleteAccount = (data: DeleteAccountFormData) => {
    deleteAccountMutation.mutate(data);
    setShowDeleteDialog(false);
  };

  const handleMfaToggle = async () => {
    if (mfaStatus?.enabled) {
      // Show disable confirmation
      const mfaCode = prompt("Enter your current MFA code to disable MFA:");
      if (mfaCode) {
        disableMfaMutation.mutate(mfaCode);
      }
    } else {
      setShowMfaSetup(true);
      refetchMfaSetup();
    }
  };

  const handleMfaEnable = () => {
    const mfaCode = prompt("Enter the 6-digit code from your authenticator app:");
    if (mfaCode) {
      enableMfaMutation.mutate(mfaCode);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied!",
      description: "Text copied to clipboard.",
    });
  };

  return (
    <div className="min-h-screen bg-background">
      <div className="container mx-auto py-8 px-4 max-w-4xl">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-foreground" data-testid="text-settings-title">
            Account Settings
          </h1>
          <p className="text-muted-foreground mt-2">
            Manage your account information, security settings, and preferences.
          </p>
        </div>

        <div className="space-y-8">
          {/* Profile Section */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <User className="h-5 w-5" />
                <span>Profile Information</span>
              </CardTitle>
              <CardDescription>
                Update your personal information and email address.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Form {...profileForm}>
                <form onSubmit={profileForm.handleSubmit(handleProfileSubmit)} className="space-y-4">
                  <FormField
                    control={profileForm.control}
                    name="name"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Full Name</FormLabel>
                        <FormControl>
                          <Input 
                            {...field} 
                            placeholder="Enter your full name"
                            data-testid="input-profile-name"
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={profileForm.control}
                    name="email"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Email Address</FormLabel>
                        <FormControl>
                          <Input 
                            {...field} 
                            type="email"
                            placeholder="Enter your email address"
                            data-testid="input-profile-email"
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <Button 
                    type="submit" 
                    disabled={updateProfileMutation.isPending}
                    data-testid="button-save-profile"
                  >
                    {updateProfileMutation.isPending ? "Saving..." : "Save Changes"}
                  </Button>
                </form>
              </Form>
            </CardContent>
          </Card>

          {/* Password Section */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Key className="h-5 w-5" />
                <span>Change Password</span>
              </CardTitle>
              <CardDescription>
                Update your password to keep your account secure.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Form {...passwordForm}>
                <form onSubmit={passwordForm.handleSubmit(handlePasswordSubmit)} className="space-y-4">
                  <FormField
                    control={passwordForm.control}
                    name="currentPassword"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Current Password</FormLabel>
                        <FormControl>
                          <Input 
                            {...field} 
                            type="password"
                            placeholder="Enter your current password"
                            data-testid="input-current-password"
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={passwordForm.control}
                    name="newPassword"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>New Password</FormLabel>
                        <FormControl>
                          <Input 
                            {...field} 
                            type="password"
                            placeholder="Enter your new password"
                            data-testid="input-new-password"
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={passwordForm.control}
                    name="confirmPassword"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Confirm New Password</FormLabel>
                        <FormControl>
                          <Input 
                            {...field} 
                            type="password"
                            placeholder="Confirm your new password"
                            data-testid="input-confirm-password"
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <Button 
                    type="submit" 
                    disabled={changePasswordMutation.isPending}
                    data-testid="button-change-password"
                  >
                    {changePasswordMutation.isPending ? "Changing..." : "Change Password"}
                  </Button>
                </form>
              </Form>
            </CardContent>
          </Card>

          {/* MFA Section */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <ShieldCheck className="h-5 w-5" />
                <span>Multi-Factor Authentication</span>
              </CardTitle>
              <CardDescription>
                Add an extra layer of security to your account.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="font-medium">Two-Factor Authentication</p>
                  <p className="text-sm text-muted-foreground">
                    {mfaStatus?.enabled 
                      ? "MFA is currently enabled for your account"
                      : "MFA is currently disabled"
                    }
                  </p>
                </div>
                <div className="flex items-center space-x-3">
                  {mfaStatus?.enabled && (
                    <Badge variant="secondary" className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300">
                      <CheckCircle className="h-3 w-3 mr-1" />
                      Enabled
                    </Badge>
                  )}
                  <Switch
                    checked={mfaStatus?.enabled || false}
                    onCheckedChange={handleMfaToggle}
                    disabled={mfaLoading || enableMfaMutation.isPending || disableMfaMutation.isPending}
                    data-testid="switch-mfa-toggle"
                  />
                </div>
              </div>

              {mfaStatus?.enabled && (
                <Alert>
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>
                    You have <strong>{mfaStatus.backupCodesCount}</strong> backup codes remaining.
                    Keep these codes safe as they can be used to access your account if you lose your device.
                  </AlertDescription>
                </Alert>
              )}

              {showMfaSetup && mfaSetupData && (
                <div className="border rounded-lg p-4 space-y-4 bg-muted/50">
                  <h4 className="font-medium">Set up MFA</h4>
                  <div className="space-y-3">
                    <p className="text-sm text-muted-foreground">
                      1. Scan the QR code with your authenticator app:
                    </p>
                    <div className="flex justify-center">
                      <img 
                        src={mfaSetupData.qrCode} 
                        alt="MFA QR Code" 
                        className="border rounded"
                        data-testid="img-mfa-qr-code"
                      />
                    </div>
                    <p className="text-sm text-muted-foreground">
                      2. Enter the 6-digit code from your app to verify:
                    </p>
                    <div className="flex space-x-2">
                      <Button 
                        onClick={handleMfaEnable}
                        disabled={enableMfaMutation.isPending}
                        data-testid="button-verify-mfa"
                      >
                        {enableMfaMutation.isPending ? "Verifying..." : "Verify & Enable"}
                      </Button>
                      <Button 
                        variant="outline" 
                        onClick={() => setShowMfaSetup(false)}
                        data-testid="button-cancel-mfa"
                      >
                        Cancel
                      </Button>
                    </div>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Account Deletion Section */}
          <Card className="border-destructive">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2 text-destructive">
                <Trash2 className="h-5 w-5" />
                <span>Delete Account</span>
              </CardTitle>
              <CardDescription>
                Permanently delete your account and all associated data. This action cannot be undone.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Alert className="mb-4">
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>
                  <strong>Warning:</strong> This will permanently delete your account, profile information, 
                  and all associated data. This action cannot be reversed.
                </AlertDescription>
              </Alert>
              <AlertDialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
                <AlertDialogTrigger asChild>
                  <Button 
                    variant="destructive" 
                    className="w-full sm:w-auto"
                    data-testid="button-delete-account"
                  >
                    Delete Account
                  </Button>
                </AlertDialogTrigger>
                <AlertDialogContent>
                  <AlertDialogHeader>
                    <AlertDialogTitle>Delete Account</AlertDialogTitle>
                    <AlertDialogDescription>
                      This action cannot be undone. This will permanently delete your account and remove all data.
                    </AlertDialogDescription>
                  </AlertDialogHeader>
                  <div className="space-y-4">
                    <div className="space-y-4">
                      <div>
                        <label className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70">
                          Password
                        </label>
                        <Input 
                          type="password"
                          placeholder="Enter your password to confirm"
                          value={deleteAccountForm.watch("currentPassword")}
                          onChange={(e) => deleteAccountForm.setValue("currentPassword", e.target.value)}
                          data-testid="input-delete-password"
                        />
                        {deleteAccountForm.formState.errors.currentPassword && (
                          <p className="text-sm font-medium text-destructive">
                            {deleteAccountForm.formState.errors.currentPassword.message}
                          </p>
                        )}
                      </div>
                      <div>
                        <label className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70">
                          Type "DELETE" to confirm
                        </label>
                        <Input 
                          placeholder="DELETE"
                          value={deleteAccountForm.watch("confirmText")}
                          onChange={(e) => deleteAccountForm.setValue("confirmText", e.target.value as any)}
                          data-testid="input-delete-confirm"
                        />
                        {deleteAccountForm.formState.errors.confirmText && (
                          <p className="text-sm font-medium text-destructive">
                            {deleteAccountForm.formState.errors.confirmText.message}
                          </p>
                        )}
                      </div>
                    </div>
                  </div>
                  <AlertDialogFooter>
                    <AlertDialogCancel data-testid="button-cancel-delete">Cancel</AlertDialogCancel>
                    <AlertDialogAction
                      onClick={deleteAccountForm.handleSubmit(handleDeleteAccount)}
                      className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                      disabled={deleteAccountMutation.isPending}
                      data-testid="button-confirm-delete"
                    >
                      {deleteAccountMutation.isPending ? "Deleting..." : "Delete Account"}
                    </AlertDialogAction>
                  </AlertDialogFooter>
                </AlertDialogContent>
              </AlertDialog>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}