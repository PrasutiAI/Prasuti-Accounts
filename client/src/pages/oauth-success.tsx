import { useEffect } from "react";
import { useLocation } from "wouter";
import { useSearch } from "wouter";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Loader2, CheckCircle } from "lucide-react";

export default function OAuthSuccess() {
  const [, setLocation] = useLocation();
  const search = useSearch();

  useEffect(() => {
    const urlParams = new URLSearchParams(search);
    const accessToken = urlParams.get('access_token');
    const refreshToken = urlParams.get('refresh_token');
    const redirect = urlParams.get('redirect') || '/dashboard';

    if (accessToken && refreshToken) {
      // Store tokens in localStorage
      localStorage.setItem('accessToken', accessToken);
      localStorage.setItem('refreshToken', refreshToken);

      // Redirect to intended destination after a brief delay
      setTimeout(() => {
        // Clean URL by removing query parameters before redirect
        const cleanRedirect = redirect.split('?')[0];
        setLocation(cleanRedirect);
      }, 1500);
    } else {
      // No tokens provided, redirect to login with error
      setLocation('/login?error=' + encodeURIComponent('Authentication failed'));
    }
  }, [search, setLocation]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-background via-background to-muted/20 p-4">
      <Card className="w-full max-w-md shadow-2xl border-border/60 bg-card/95 backdrop-blur-sm">
        <CardHeader className="space-y-6 text-center pb-8">
          <div className="flex justify-center mb-2">
            <div className="w-16 h-16 bg-gradient-to-br from-green-500 via-green-500/90 to-green-500/80 rounded-2xl flex items-center justify-center shadow-lg">
              <CheckCircle className="h-8 w-8 text-white drop-shadow-sm" />
            </div>
          </div>
          <div className="space-y-3">
            <CardTitle className="text-2xl font-bold text-foreground">Authentication Successful</CardTitle>
            <CardDescription className="text-base text-muted-foreground/80 font-medium">
              Redirecting you to your destination...
            </CardDescription>
          </div>
        </CardHeader>
        <CardContent className="flex justify-center pb-8">
          <div className="flex items-center space-x-3">
            <Loader2 className="h-5 w-5 animate-spin text-primary" />
            <span className="text-sm text-muted-foreground">Please wait</span>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}