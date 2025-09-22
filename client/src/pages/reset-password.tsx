import { useState, useEffect } from "react";
import { useMutation } from "@tanstack/react-query";
import { Link, useLocation } from "wouter";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useToast } from "@/hooks/use-toast";
import { Shield, ArrowLeft, Check, AlertCircle, Eye, EyeOff } from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { resetPasswordSchema, type ResetPasswordRequest } from "@shared/schema";
import { z } from "zod";

// Extended schema with password confirmation
const resetPasswordFormSchema = resetPasswordSchema.extend({
  confirmPassword: z.string().min(8, "Please confirm your password"),
}).refine(
  (data) => data.password === data.confirmPassword,
  {
    message: "Passwords do not match",
    path: ["confirmPassword"],
  }
);

type ResetPasswordFormRequest = z.infer<typeof resetPasswordFormSchema>;

export default function ResetPassword() {
  const [location] = useLocation();
  const [isSubmitted, setIsSubmitted] = useState(false);
  const [tokenError, setTokenError] = useState<string | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const { toast } = useToast();

  // Extract token from URL query parameters
  const urlParams = new URLSearchParams(location.split('?')[1] || '');
  const token = urlParams.get('token');

  const form = useForm<ResetPasswordFormRequest>({
    resolver: zodResolver(resetPasswordFormSchema),
    defaultValues: {
      token: token || "",
      password: "",
      confirmPassword: "",
    },
  });

  // Validate token on page load
  useEffect(() => {
    if (!token) {
      setTokenError("No reset token provided. Please check your email for the correct link.");
      return;
    }
    
    // Set token in form
    form.setValue('token', token);
  }, [token, form]);

  const resetPasswordMutation = useMutation({
    mutationFn: async (data: ResetPasswordFormRequest) => {
      const response = await apiRequest('POST', '/api/auth/reset-password', {
        token: data.token,
        password: data.password,
      });
      return response.json();
    },
    onSuccess: (data) => {
      setIsSubmitted(true);
      // Clear form data for security
      form.reset();
      toast({
        title: "Password reset successful",
        description: data.message || "Your password has been reset successfully. You can now sign in with your new password.",
      });
    },
    onError: (error: any) => {
      const message = error.message || "Failed to reset password";
      
      // Handle specific error cases
      if (message.includes('Invalid or expired')) {
        setTokenError("This reset link has expired or is invalid. Please request a new password reset.");
      } else {
        toast({
          title: "Error",
          description: message,
          variant: "destructive",
        });
      }
    },
  });

  const onSubmit = (data: ResetPasswordFormRequest) => {
    if (!token) {
      setTokenError("No reset token provided. Please check your email for the correct link.");
      return;
    }
    resetPasswordMutation.mutate(data);
  };

  // Show success page after successful reset
  if (isSubmitted) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="space-y-1 text-center">
            <div className="flex justify-center mb-4">
              <div className="w-12 h-12 bg-green-500 rounded-lg flex items-center justify-center">
                <Check className="h-6 w-6 text-white" />
              </div>
            </div>
            <CardTitle className="text-2xl font-semibold">Password Reset Successful</CardTitle>
            <CardDescription>
              Your password has been reset successfully. You can now sign in with your new password.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <Link href="/login">
                <Button className="w-full" data-testid="button-go-to-login">
                  Sign in with new password
                </Button>
              </Link>
              
              <div className="text-center">
                <p className="text-sm text-muted-foreground">
                  For security reasons, you have been logged out of all devices.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  // Show error page if token is invalid
  if (tokenError) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="space-y-1 text-center">
            <div className="flex justify-center mb-4">
              <div className="w-12 h-12 bg-destructive rounded-lg flex items-center justify-center">
                <AlertCircle className="h-6 w-6 text-destructive-foreground" />
              </div>
            </div>
            <CardTitle className="text-2xl font-semibold">Invalid Reset Link</CardTitle>
            <CardDescription>
              {tokenError}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <Alert>
                <AlertCircle className="h-4 w-4" />
                <AlertDescription>
                  Reset links expire after 1 hour for security purposes.
                </AlertDescription>
              </Alert>
              
              <div className="flex flex-col space-y-2">
                <Link href="/forgot-password">
                  <Button className="w-full" data-testid="button-request-new-reset">
                    Request new password reset
                  </Button>
                </Link>
                
                <Link href="/login">
                  <Button variant="outline" className="w-full" data-testid="button-back-to-login">
                    <ArrowLeft className="h-4 w-4 mr-2" />
                    Back to sign in
                  </Button>
                </Link>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="space-y-1 text-center">
          <div className="flex justify-center mb-4">
            <div className="w-12 h-12 bg-primary rounded-lg flex items-center justify-center">
              <Shield className="h-6 w-6 text-primary-foreground" />
            </div>
          </div>
          <CardTitle className="text-2xl font-semibold">Set New Password</CardTitle>
          <CardDescription>
            Enter your new password below. Make sure it's strong and unique.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              <FormField
                control={form.control}
                name="password"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>New Password</FormLabel>
                    <FormControl>
                      <div className="relative">
                        <Input 
                          type={showPassword ? "text" : "password"}
                          placeholder="Enter new password"
                          data-testid="input-password"
                          {...field} 
                        />
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                          onClick={() => setShowPassword(!showPassword)}
                          data-testid="button-toggle-password"
                        >
                          {showPassword ? (
                            <EyeOff className="h-4 w-4" />
                          ) : (
                            <Eye className="h-4 w-4" />
                          )}
                        </Button>
                      </div>
                    </FormControl>
                    <FormMessage />
                    <div className="text-xs text-muted-foreground">
                      Password must be at least 8 characters long
                    </div>
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="confirmPassword"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Confirm New Password</FormLabel>
                    <FormControl>
                      <div className="relative">
                        <Input 
                          type={showConfirmPassword ? "text" : "password"}
                          placeholder="Confirm new password"
                          data-testid="input-confirm-password"
                          {...field} 
                        />
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                          onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                          data-testid="button-toggle-confirm-password"
                        >
                          {showConfirmPassword ? (
                            <EyeOff className="h-4 w-4" />
                          ) : (
                            <Eye className="h-4 w-4" />
                          )}
                        </Button>
                      </div>
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <Button 
                type="submit" 
                className="w-full"
                disabled={resetPasswordMutation.isPending}
                data-testid="button-reset-password"
              >
                {resetPasswordMutation.isPending ? "Resetting password..." : "Reset password"}
              </Button>
            </form>
          </Form>

          <div className="mt-6 text-center">
            <Link href="/login">
              <Button variant="link" className="p-0 h-auto font-normal" data-testid="link-back-to-login">
                <ArrowLeft className="h-4 w-4 mr-2" />
                Back to sign in
              </Button>
            </Link>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}