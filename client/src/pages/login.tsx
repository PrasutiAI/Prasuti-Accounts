import { useState, useEffect } from "react";
import { useMutation } from "@tanstack/react-query";
import { useLocation, Link } from "wouter";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/use-auth";
import { Shield } from "lucide-react";
import { SiGoogle } from "react-icons/si";
import { apiRequest } from "@/lib/queryClient";
import { loginSchema, type LoginRequest } from "@shared/schema";

type LoginForm = LoginRequest;

export default function Login() {
  const [, setLocation] = useLocation();
  const [requiresMfa, setRequiresMfa] = useState(false);
  const [redirectUrl, setRedirectUrl] = useState<string | null>(null);
  const { toast } = useToast();
  const { isAuthenticated, isLoading } = useAuth();
  
  // Check for registration success message and extract redirectUrl
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    
    if (urlParams.get('registered') === 'true') {
      toast({
        title: "Registration successful",
        description: "Please check your email for verification instructions before signing in.",
      });
    }
    
    // Extract redirectUrl from query parameters
    const redirect = urlParams.get('redirectUrl');
    if (redirect) {
      setRedirectUrl(redirect);
    }
  }, [toast]);

  // Auto-redirect if user is already authenticated
  useEffect(() => {
    if (!isLoading && isAuthenticated) {
      // User is already logged in, redirect them to their destination
      const redirectToDestination = async () => {
        let validatedDestination = "/dashboard";
        
        if (redirectUrl) {
          try {
            const validationResponse = await apiRequest('POST', '/api/auth/validate-redirect', {
              redirectUrl: redirectUrl
            });
            const validationData = await validationResponse.json();
            
            if (validationData.valid) {
              validatedDestination = validationData.normalizedUrl;
            } else {
              toast({
                title: "Invalid redirect URL",
                description: `Redirecting to dashboard instead. ${validationData.error}`,
                variant: "destructive",
              });
              validatedDestination = "/dashboard";
            }
          } catch (error) {
            toast({
              title: "Redirect validation failed",
              description: "Redirecting to dashboard for security.",
              variant: "destructive",
            });
            validatedDestination = "/dashboard";
          }
        }
        
        // Handle redirection with JWT details appended to all redirect URLs
        const currentOrigin = window.location.origin;
        
        // Convert relative URLs to absolute for processing
        let absoluteDestination: string;
        try {
          // If validatedDestination is relative, make it absolute
          if (validatedDestination.startsWith('/')) {
            absoluteDestination = currentOrigin + validatedDestination;
          } else {
            absoluteDestination = validatedDestination;
          }
          
          // Verify it's a valid URL
          new URL(absoluteDestination);
        } catch (error) {
          // Fallback for invalid URLs
          setLocation('/dashboard');
          return;
        }
        
        // Append JWT details to all redirect URLs (both same-origin and cross-origin)
        let finalDestination = absoluteDestination;
        
        // Get stored tokens
        const accessToken = localStorage.getItem('accessToken');
        
        if (accessToken) {
          try {
            const tokenResponse = await apiRequest('POST', '/api/auth/append-tokens-to-url', {
              url: absoluteDestination,
              accessToken
            });
            const tokenData = await tokenResponse.json();
            if (tokenData.urlWithTokens) {
              finalDestination = tokenData.urlWithTokens;
            }
          } catch (error) {
            // If token appending fails, proceed with original URL
            console.warn('Failed to append tokens to URL:', error);
          }
        }
        
        try {
          const destinationUrl = new URL(finalDestination);
          
          if (destinationUrl.origin === currentOrigin) {
            // Same-origin redirect: use router navigation with JWT details in URL
            setLocation(destinationUrl.pathname + destinationUrl.search + destinationUrl.hash);
          } else {
            // Cross-origin redirect: use full URL replacement
            window.location.replace(finalDestination);
          }
        } catch (error) {
          // Fallback: treat as same-origin path if URL parsing fails
          setLocation('/dashboard');
        }
      };

      redirectToDestination();
    }
  }, [isLoading, isAuthenticated, redirectUrl, setLocation, toast]);

  const form = useForm<LoginForm>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      identifier: "",
      password: "",
      mfaCode: "",
    },
  });

  const loginMutation = useMutation({
    mutationFn: async (data: LoginForm) => {
      const requestData = { ...data };
      if (redirectUrl) {
        requestData.redirectUrl = redirectUrl;
      }
      const response = await apiRequest('POST', '/api/auth/login', requestData);
      return response.json();
    },
    onSuccess: async (data) => {
      // Store tokens
      localStorage.setItem('accessToken', data.accessToken);
      localStorage.setItem('refreshToken', data.refreshToken);
      
      toast({
        title: "Login successful",
        description: `Welcome back, ${data.user.name}!`,
      });
      
      // Use redirect URL with JWT details appended (if provided by backend), otherwise default
      let finalDestination = data.redirectUrl || "/dashboard";
      
      // If no redirectUrl was provided by backend, append JWT details to default destination
      if (!data.redirectUrl) {
        const currentOrigin = window.location.origin;
        
        // Convert relative URLs to absolute for processing
        let absoluteDestination: string;
        try {
          // If finalDestination is relative, make it absolute
          if (finalDestination.startsWith('/')) {
            absoluteDestination = currentOrigin + finalDestination;
          } else {
            absoluteDestination = finalDestination;
          }
          
          // Verify it's a valid URL
          new URL(absoluteDestination);
        } catch (error) {
          // Fallback for invalid URLs
          setLocation('/dashboard');
          return;
        }
        
        // Append JWT details to default destination
        try {
          const tokenResponse = await apiRequest('POST', '/api/auth/append-tokens-to-url', {
            url: absoluteDestination,
            accessToken: data.accessToken
          });
          const tokenData = await tokenResponse.json();
          if (tokenData.urlWithTokens) {
            finalDestination = tokenData.urlWithTokens;
          }
        } catch (error) {
          // If token appending fails, use absolute destination
          console.warn('Failed to append tokens to URL:', error);
          finalDestination = absoluteDestination;
        }
      }
      
      // Handle redirect 
      try {
        const destinationUrl = new URL(finalDestination);
        const currentOrigin = window.location.origin;
        
        // Check if redirect is to same origin or external
        if (destinationUrl.origin === currentOrigin) {
          // Same-origin redirect: use router navigation with JWT details in URL
          setLocation(destinationUrl.pathname + destinationUrl.search + destinationUrl.hash);
        } else {
          // Cross-origin redirect: use full URL replacement
          window.location.replace(finalDestination);
        }
      } catch (error) {
        // Fallback: treat as same-origin path if URL parsing fails
        setLocation('/dashboard');
      }
    },
    onError: (error: any) => {
      const message = error.message || "Login failed";
      
      if (message.includes("MFA code required")) {
        setRequiresMfa(true);
        toast({
          title: "MFA Required",
          description: "Please enter your MFA code to continue",
          variant: "default",
        });
      } else {
        toast({
          title: "Login failed",
          description: message,
          variant: "destructive",
        });
      }
    },
  });

  const onSubmit = (data: LoginForm) => {
    loginMutation.mutate(data);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-background via-background to-muted/20 p-4 relative overflow-hidden">
      {/* Background Pattern */}
      <div className="absolute inset-0 opacity-20">
        <div className="absolute top-0 -left-4 w-72 h-72 bg-primary/10 rounded-full mix-blend-multiply filter blur-xl animate-blob"></div>
        <div className="absolute top-0 -right-4 w-72 h-72 bg-secondary/10 rounded-full mix-blend-multiply filter blur-xl animate-blob animation-delay-2000"></div>
        <div className="absolute -bottom-8 left-20 w-72 h-72 bg-accent/10 rounded-full mix-blend-multiply filter blur-xl animate-blob animation-delay-4000"></div>
      </div>
      
      <Card className="w-full max-w-md shadow-2xl border-border/60 bg-card/95 backdrop-blur-sm animate-scale-in">
        <CardHeader className="space-y-6 text-center pb-8">
          <div className="flex justify-center mb-2">
            <div className="w-16 h-16 bg-gradient-to-br from-primary via-primary/90 to-primary/80 rounded-2xl flex items-center justify-center shadow-lg hover:shadow-xl transition-all duration-300 hover:scale-105 group">
              <Shield className="h-8 w-8 text-primary-foreground drop-shadow-sm group-hover:drop-shadow-md transition-all duration-300" />
            </div>
          </div>
          <div className="space-y-3">
            <CardTitle className="text-3xl font-bold text-foreground">Welcome back</CardTitle>
            <CardDescription className="text-base text-muted-foreground/80 font-medium">
              Sign in to your Prasuti.AI account
            </CardDescription>
          </div>
        </CardHeader>
        <CardContent>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              <FormField
                control={form.control}
                name="identifier"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Email or Phone Number</FormLabel>
                    <FormControl>
                      <Input 
                        type="text" 
                        placeholder="Enter your email or phone number"
                        data-testid="input-identifier"
                        {...field} 
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              
              <FormField
                control={form.control}
                name="password"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Password</FormLabel>
                    <FormControl>
                      <Input 
                        type="password" 
                        placeholder="Enter your password"
                        data-testid="input-password"
                        {...field} 
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              {requiresMfa && (
                <FormField
                  control={form.control}
                  name="mfaCode"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>MFA Code</FormLabel>
                      <FormControl>
                        <Input 
                          placeholder="Enter your 6-digit MFA code"
                          data-testid="input-mfa-code"
                          {...field} 
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              )}

              <Button 
                type="submit" 
                className="w-full h-12 text-base font-semibold shadow-lg hover:shadow-xl transition-all duration-300 hover:scale-105 bg-gradient-to-r from-primary to-primary/90 hover:from-primary/90 hover:to-primary/80"
                disabled={loginMutation.isPending}
                data-testid="button-login"
              >
                {loginMutation.isPending ? (
                  <div className="flex items-center space-x-2">
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                    <span>Signing in...</span>
                  </div>
                ) : "Sign In"}
              </Button>
            </form>
          </Form>

          {/* OAuth Section */}
          <div className="mt-6">
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <span className="w-full border-t" />
              </div>
              <div className="relative flex justify-center text-xs uppercase">
                <span className="bg-card px-2 text-muted-foreground">Or continue with</span>
              </div>
            </div>
            
            <div className="mt-6">
              <Button
                type="button"
                variant="outline"
                className="w-full h-12 text-base font-medium border-border/60 hover:bg-accent/50 hover:border-border transition-all duration-300"
                onClick={() => {
                  const baseUrl = '/api/auth/google';
                  const redirectParam = redirectUrl ? `?redirectUrl=${encodeURIComponent(redirectUrl)}` : '';
                  window.location.href = baseUrl + redirectParam;
                }}
                data-testid="button-google-login"
              >
                <SiGoogle className="w-5 h-5 mr-3" />
                Sign in with Google
              </Button>
            </div>
          </div>

          <div className="mt-8 text-center text-sm text-muted-foreground space-y-3">
            <div>
              <Link href="/forgot-password">
                <Button variant="link" className="p-0 h-auto font-medium text-primary hover:text-primary/80 transition-colors duration-200" data-testid="link-forgot-password">
                  Forgot your password?
                </Button>
              </Link>
            </div>
            <div className="flex items-center justify-center space-x-1">
              <span>Don't have an account?</span>
              <Link href={redirectUrl ? `/register?redirectUrl=${encodeURIComponent(redirectUrl)}` : "/register"}>
                <Button variant="link" className="p-0 h-auto font-semibold text-primary hover:text-primary/80 transition-colors duration-200" data-testid="link-register">
                  Sign up
                </Button>
              </Link>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
