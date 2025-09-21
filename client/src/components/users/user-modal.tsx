import { useEffect } from "react";
import { useMutation } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { X } from "lucide-react";

const userFormSchema = z.object({
  email: z.string().email("Invalid email address"),
  name: z.string().min(1, "Name is required"),
  password: z.string().min(8, "Password must be at least 8 characters").optional(),
  role: z.enum(["admin", "developer", "user", "guest"]),
  status: z.enum(["active", "inactive", "pending", "blocked"]),
  sendWelcomeEmail: z.boolean().optional(),
  requireMfa: z.boolean().optional(),
});

type UserForm = z.infer<typeof userFormSchema>;

interface UserModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  user?: any;
  onSuccess?: () => void;
}

export default function UserModal({ open, onOpenChange, user, onSuccess }: UserModalProps) {
  const { toast } = useToast();
  const isEditMode = !!user;

  const form = useForm<UserForm>({
    resolver: zodResolver(userFormSchema),
    defaultValues: {
      email: "",
      name: "",
      password: "",
      role: "user",
      status: "active",
      sendWelcomeEmail: true,
      requireMfa: false,
    },
  });

  // Update form when user changes
  useEffect(() => {
    if (user) {
      form.reset({
        email: user.email,
        name: user.name,
        role: user.role,
        status: user.status,
        sendWelcomeEmail: false,
        requireMfa: user.mfaEnabled || false,
      });
    } else {
      form.reset({
        email: "",
        name: "",
        password: "",
        role: "user",
        status: "active",
        sendWelcomeEmail: true,
        requireMfa: false,
      });
    }
  }, [user, form]);

  const createUserMutation = useMutation({
    mutationFn: async (data: UserForm) => {
      const endpoint = isEditMode ? `/api/users/${user.id}` : '/api/users';
      const method = isEditMode ? 'PATCH' : 'POST';
      
      const payload = isEditMode 
        ? { 
            name: data.name, 
            role: data.role, 
            status: data.status 
          }
        : data;

      const response = await apiRequest(method, endpoint, payload);
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: isEditMode ? "User updated" : "User created",
        description: isEditMode 
          ? "User has been successfully updated"
          : "User has been successfully created",
      });
      onSuccess?.();
      onOpenChange(false);
      form.reset();
    },
    onError: (error: any) => {
      toast({
        title: isEditMode ? "Failed to update user" : "Failed to create user",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: UserForm) => {
    createUserMutation.mutate(data);
  };

  const handleClose = () => {
    onOpenChange(false);
    form.reset();
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <div className="flex items-center justify-between">
            <DialogTitle>
              {isEditMode ? "Edit User" : "Create New User"}
            </DialogTitle>
            <Button
              variant="ghost"
              size="icon"
              onClick={handleClose}
              data-testid="button-close-modal"
            >
              <X className="h-4 w-4" />
            </Button>
          </div>
        </DialogHeader>

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
                      placeholder="Enter full name"
                      data-testid="input-user-name"
                      {...field} 
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="email"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Email Address</FormLabel>
                  <FormControl>
                    <Input 
                      type="email" 
                      placeholder="Enter email address"
                      disabled={isEditMode} // Don't allow email changes in edit mode
                      data-testid="input-user-email"
                      {...field} 
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="role"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Role</FormLabel>
                  <Select 
                    onValueChange={field.onChange} 
                    defaultValue={field.value}
                    data-testid="select-user-role"
                  >
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder="Select a role" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="admin">Admin</SelectItem>
                      <SelectItem value="developer">Developer</SelectItem>
                      <SelectItem value="user">User</SelectItem>
                      <SelectItem value="guest">Guest</SelectItem>
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="status"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Status</FormLabel>
                  <Select 
                    onValueChange={field.onChange} 
                    defaultValue={field.value}
                    data-testid="select-user-status"
                  >
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder="Select status" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="active">Active</SelectItem>
                      <SelectItem value="inactive">Inactive</SelectItem>
                      <SelectItem value="pending">Pending</SelectItem>
                      <SelectItem value="blocked">Blocked</SelectItem>
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />

            {!isEditMode && (
              <FormField
                control={form.control}
                name="password"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Password</FormLabel>
                    <FormControl>
                      <Input 
                        type="password" 
                        placeholder="Enter temporary password"
                        data-testid="input-user-password"
                        {...field} 
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            )}

            {!isEditMode && (
              <>
                <FormField
                  control={form.control}
                  name="sendWelcomeEmail"
                  render={({ field }) => (
                    <FormItem className="flex items-center space-x-2 space-y-0">
                      <FormControl>
                        <Checkbox
                          checked={field.value}
                          onCheckedChange={field.onChange}
                          data-testid="checkbox-welcome-email"
                        />
                      </FormControl>
                      <FormLabel className="text-sm font-normal">
                        Send welcome email
                      </FormLabel>
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="requireMfa"
                  render={({ field }) => (
                    <FormItem className="flex items-center space-x-2 space-y-0">
                      <FormControl>
                        <Checkbox
                          checked={field.value}
                          onCheckedChange={field.onChange}
                          data-testid="checkbox-require-mfa"
                        />
                      </FormControl>
                      <FormLabel className="text-sm font-normal">
                        Require MFA setup
                      </FormLabel>
                    </FormItem>
                  )}
                />
              </>
            )}

            <div className="flex space-x-3 pt-4">
              <Button 
                type="submit" 
                className="flex-1"
                disabled={createUserMutation.isPending}
                data-testid="button-save-user"
              >
                {createUserMutation.isPending 
                  ? (isEditMode ? "Updating..." : "Creating...") 
                  : (isEditMode ? "Update User" : "Create User")
                }
              </Button>
              <Button 
                type="button" 
                variant="secondary"
                className="flex-1"
                onClick={handleClose}
                data-testid="button-cancel-user"
              >
                Cancel
              </Button>
            </div>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
