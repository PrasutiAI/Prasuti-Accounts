import { useMutation } from "@tanstack/react-query";
import { useLocation, Link } from "wouter";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { useToast } from "@/hooks/use-toast";
import { Shield, UserPlus } from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { registerSchema as sharedRegisterSchema } from "@shared/schema";
import { useEffect, useState } from "react";

const registerSchema = sharedRegisterSchema.extend({
  confirmPassword: z.string().min(8, "Please confirm your password"),
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
});

type RegisterForm = z.infer<typeof registerSchema>;

export default function Register() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const [redirectUrl, setRedirectUrl] = useState<string | null>(null);

  // Extract redirectUrl from query parameters
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const redirect = urlParams.get('redirectUrl');
    if (redirect) {
      setRedirectUrl(redirect);
    }
  }, []);

  const form = useForm<RegisterForm>({
    resolver: zodResolver(registerSchema),
    defaultValues: {
      name: "",
      email: "",
      phoneNumber: "",
      password: "",
      confirmPassword: "",
    },
  });

  const registerMutation = useMutation({
    mutationFn: async (data: RegisterForm) => {
      const { confirmPassword, ...registerData } = data;
      // Include redirectUrl in registration data if provided
      const requestData = redirectUrl 
        ? { ...registerData, redirectUrl }
        : registerData;
      const response = await apiRequest('POST', '/api/auth/register', requestData);
      return response.json();
    },
    onSuccess: (data) => {
      toast({
        title: "Registration successful",
        description: data.message || "Please check your email for verification instructions.",
      });
      
      // Redirect to login page with success message and redirectUrl if provided
      const loginUrl = redirectUrl 
        ? `/login?registered=true&redirectUrl=${encodeURIComponent(redirectUrl)}`
        : "/login?registered=true";
      setLocation(loginUrl);
    },
    onError: (error: any) => {
      const message = error.message || "Registration failed";
      
      // Handle specific error cases with comprehensive error handling
      if (message.includes("already exists") || message.includes("User already exists")) {
        form.setError("email", {
          type: "manual",
          message: "An account with this email already exists",
        });
        toast({
          title: "Email already registered",
          description: "Please use a different email address or try signing in instead.",
          variant: "destructive",
        });
      } else if (message.includes("Password")) {
        form.setError("password", {
          type: "manual",
          message: "Password requirements not met",
        });
        toast({
          title: "Password error",
          description: message,
          variant: "destructive",
        });
      } else if (message.includes("email") || message.includes("Email")) {
        form.setError("email", {
          type: "manual",
          message: "Please enter a valid email address",
        });
        toast({
          title: "Invalid email",
          description: message,
          variant: "destructive",
        });
      } else if (message.includes("Name") || message.includes("name")) {
        form.setError("name", {
          type: "manual",
          message: "Please enter a valid name",
        });
        toast({
          title: "Invalid name",
          description: message,
          variant: "destructive",
        });
      } else if (message.includes("phone") || message.includes("Phone")) {
        form.setError("phoneNumber", {
          type: "manual",
          message: "Please enter a valid phone number",
        });
        toast({
          title: "Invalid phone number",
          description: message,
          variant: "destructive",
        });
      } else if (message.includes("rate limit") || message.includes("Too many")) {
        toast({
          title: "Too many attempts",
          description: "Please wait a few minutes before trying again.",
          variant: "destructive",
        });
      } else if (message.includes("network") || message.includes("Network")) {
        toast({
          title: "Network error",
          description: "Please check your internet connection and try again.",
          variant: "destructive",
        });
      } else {
        toast({
          title: "Registration failed",
          description: message || "An unexpected error occurred. Please try again.",
          variant: "destructive",
        });
      }
    },
  });

  const onSubmit = (data: RegisterForm) => {
    registerMutation.mutate(data);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="space-y-1 text-center">
          <div className="flex justify-center mb-4">
            <div className="w-12 h-12 bg-primary rounded-lg flex items-center justify-center">
              <UserPlus className="h-6 w-6 text-primary-foreground" />
            </div>
          </div>
          <CardTitle className="text-2xl font-semibold">Create account</CardTitle>
          <CardDescription>
            Join Prasuti.AI Hub and start building
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              <FormField
                control={form.control}
                name="name"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Full Name</FormLabel>
                    <FormControl>
                      <Input 
                        type="text" 
                        placeholder="Enter your full name"
                        data-testid="input-name"
                        {...field} 
                      />
                    </FormControl>
                    <FormMessage data-testid="error-name" />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="email"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Email</FormLabel>
                    <FormControl>
                      <Input 
                        type="email" 
                        placeholder="Enter your email"
                        data-testid="input-email"
                        {...field} 
                      />
                    </FormControl>
                    <FormMessage data-testid="error-email" />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="phoneNumber"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Phone Number (Optional)</FormLabel>
                    <FormControl>
                      <Input 
                        type="tel" 
                        placeholder="Enter your phone number (e.g., +1234567890)"
                        data-testid="input-phone-number"
                        {...field} 
                      />
                    </FormControl>
                    <FormMessage data-testid="error-phone-number" />
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
                        placeholder="Create a password (min 8 characters)"
                        data-testid="input-password"
                        {...field} 
                      />
                    </FormControl>
                    <FormMessage data-testid="error-password" />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="confirmPassword"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Confirm Password</FormLabel>
                    <FormControl>
                      <Input 
                        type="password" 
                        placeholder="Confirm your password"
                        data-testid="input-confirm-password"
                        {...field} 
                      />
                    </FormControl>
                    <FormMessage data-testid="error-confirm-password" />
                  </FormItem>
                )}
              />

              <Button 
                type="submit" 
                className="w-full"
                disabled={registerMutation.isPending}
                data-testid="button-register"
              >
                {registerMutation.isPending ? "Creating account..." : "Create Account"}
              </Button>
            </form>
          </Form>

          <div className="mt-6 text-center text-sm text-muted-foreground">
            Already have an account?{" "}
            <Link href="/login">
              <Button variant="link" className="p-0 h-auto font-normal" data-testid="link-login">
                Sign in
              </Button>
            </Link>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}