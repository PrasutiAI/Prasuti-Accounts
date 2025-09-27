import { useEffect, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { useLocation, Link } from "wouter";
import { useSearch } from "wouter";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useToast } from "@/hooks/use-toast";
import { Shield, CheckCircle, XCircle, Loader2, Mail } from "lucide-react";
import { apiRequest } from "@/lib/queryClient";

export default function VerifyEmail() {
  const [, setLocation] = useLocation();
  const search = useSearch();
  const { toast } = useToast();
  const [verificationStatus, setVerificationStatus] = useState<'loading' | 'success' | 'error' | 'invalid' | 'redirecting'>('loading');
  const [redirectUrl, setRedirectUrl] = useState<string | null>(null);

  // Extract token from URL parameters
  const urlParams = new URLSearchParams(search);
  const token = urlParams.get('token');

  const verifyMutation = useMutation({
    mutationFn: async (verificationToken: string) => {
      const response = await apiRequest('POST', '/api/auth/verify', { token: verificationToken });
      return response.json();
    },
    onSuccess: (data) => {
      setVerificationStatus('success');
      toast({
        title: "Email verified successfully",
        description: data.message || "Your email has been verified. You can now sign in.",
      });
      
      // Handle redirect after successful verification
      const destination = data.redirectUrl || "/login";
      setRedirectUrl(destination);
      
      // Show success message briefly, then redirect
      setTimeout(() => {
        setVerificationStatus('redirecting');
        setTimeout(() => {
          setLocation(destination);
        }, 2000); // Show redirecting message for 2 seconds
      }, 2000); // Show success message for 2 seconds
    },
    onError: (error: any) => {
      setVerificationStatus('error');
      const message = error.message || "Email verification failed";
      toast({
        title: "Verification failed",
        description: message,
        variant: "destructive",
      });
    },
  });

  useEffect(() => {
    if (!token) {
      setVerificationStatus('invalid');
      return;
    }

    // Automatically verify when component mounts with a valid token
    verifyMutation.mutate(token);
  }, [token]);

  const handleResendVerification = () => {
    // This would typically require the user's email
    // For now, redirect to registration or login
    setLocation('/register');
  };

  const renderContent = () => {
    switch (verificationStatus) {
      case 'loading':
        return (
          <div className="text-center">
            <div className="flex justify-center mb-4">
              <div className="w-12 h-12 bg-primary rounded-lg flex items-center justify-center">
                <Loader2 className="h-6 w-6 text-primary-foreground animate-spin" />
              </div>
            </div>
            <CardTitle className="text-xl font-semibold mb-2">Verifying your email</CardTitle>
            <CardDescription data-testid="text-verifying">
              Please wait while we verify your email address...
            </CardDescription>
          </div>
        );

      case 'success':
        return (
          <div className="text-center">
            <div className="flex justify-center mb-4">
              <div className="w-12 h-12 bg-green-500 rounded-lg flex items-center justify-center">
                <CheckCircle className="h-6 w-6 text-white" />
              </div>
            </div>
            <CardTitle className="text-xl font-semibold mb-2">Email verified!</CardTitle>
            <CardDescription className="mb-6" data-testid="text-success">
              Your email has been successfully verified. Redirecting you shortly...
            </CardDescription>
            <div className="space-y-3">
              <Link href={redirectUrl || "/login"}>
                <Button className="w-full" data-testid="button-go-to-login">
                  Continue to {redirectUrl && !redirectUrl.includes('/login') ? 'Application' : 'Sign In'}
                </Button>
              </Link>
            </div>
          </div>
        );

      case 'redirecting':
        return (
          <div className="text-center">
            <div className="flex justify-center mb-4">
              <div className="w-12 h-12 bg-primary rounded-lg flex items-center justify-center">
                <Loader2 className="h-6 w-6 text-primary-foreground animate-spin" />
              </div>
            </div>
            <CardTitle className="text-xl font-semibold mb-2">Redirecting...</CardTitle>
            <CardDescription data-testid="text-redirecting">
              Taking you to your destination...
            </CardDescription>
          </div>
        );

      case 'error':
        return (
          <div className="text-center">
            <div className="flex justify-center mb-4">
              <div className="w-12 h-12 bg-red-500 rounded-lg flex items-center justify-center">
                <XCircle className="h-6 w-6 text-white" />
              </div>
            </div>
            <CardTitle className="text-xl font-semibold mb-2">Verification failed</CardTitle>
            <CardDescription className="mb-6" data-testid="text-error">
              The verification link may have expired or is invalid. Please try again.
            </CardDescription>
            <div className="space-y-3">
              <Button 
                onClick={handleResendVerification} 
                variant="outline" 
                className="w-full"
                data-testid="button-resend"
              >
                <Mail className="h-4 w-4 mr-2" />
                Get new verification link
              </Button>
              <Link href="/login">
                <Button variant="ghost" className="w-full" data-testid="button-back-to-login">
                  Back to Sign In
                </Button>
              </Link>
            </div>
          </div>
        );

      case 'invalid':
        return (
          <div className="text-center">
            <div className="flex justify-center mb-4">
              <div className="w-12 h-12 bg-yellow-500 rounded-lg flex items-center justify-center">
                <Mail className="h-6 w-6 text-white" />
              </div>
            </div>
            <CardTitle className="text-xl font-semibold mb-2">Invalid verification link</CardTitle>
            <CardDescription className="mb-6" data-testid="text-invalid">
              This verification link is not valid. Please check your email for the correct link.
            </CardDescription>
            <div className="space-y-3">
              <Link href="/register">
                <Button variant="outline" className="w-full" data-testid="button-register">
                  Create Account
                </Button>
              </Link>
              <Link href="/login">
                <Button variant="ghost" className="w-full" data-testid="button-login">
                  Sign In
                </Button>
              </Link>
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          {renderContent()}
        </CardHeader>
      </Card>
    </div>
  );
}