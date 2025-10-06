import { useState } from "react";
import { useLocation } from "wouter";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useMutation } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import Sidebar from "@/components/layout/sidebar";
import Header from "@/components/layout/header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Upload, CheckCircle2, XCircle, AlertCircle } from "lucide-react";

const uploadSchema = z.object({
  file: z.any().refine((files) => files?.length > 0, "CSV file is required"),
});

type UploadForm = z.infer<typeof uploadSchema>;

interface BulkUploadResult {
  success: {
    email: string;
    name: string;
    defaultPassword: string;
  }[];
  failures: {
    email: string;
    name: string;
    reason: string;
  }[];
}

export default function BulkUpload() {
  const { toast } = useToast();
  const [, setLocation] = useLocation();
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [uploadResult, setUploadResult] = useState<BulkUploadResult | null>(null);

  const form = useForm<UploadForm>({
    resolver: zodResolver(uploadSchema),
    defaultValues: {
      file: undefined,
    },
  });

  const uploadMutation = useMutation({
    mutationFn: async (data: UploadForm) => {
      const formData = new FormData();
      formData.append('file', data.file[0]);
      
      const accessToken = localStorage.getItem('accessToken');
      const response = await fetch('/api/admin/bulk-upload', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
        },
        body: formData,
        credentials: 'include',
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Upload failed');
      }

      return response.json();
    },
    onSuccess: (data: BulkUploadResult) => {
      setUploadResult(data);
      toast({
        title: "Upload complete",
        description: `${data.success.length} users created successfully, ${data.failures.length} failed`,
      });
      form.reset();
    },
    onError: (error: Error) => {
      toast({
        title: "Upload failed",
        description: error.message || "Failed to upload CSV file",
        variant: "destructive",
      });
    },
  });

  const handleSubmit = (data: UploadForm) => {
    uploadMutation.mutate(data);
  };

  return (
    <div className="min-h-screen flex bg-background">
      <Sidebar 
        collapsed={sidebarCollapsed} 
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
        currentPage="bulk-upload"
      />
      
      <div className="flex-1 flex flex-col">
        <Header onSidebarToggle={() => setSidebarCollapsed(!sidebarCollapsed)} />
        
        <main className="flex-1 p-6 overflow-auto">
          <div className="flex justify-between items-center mb-6">
            <div>
              <h1 className="text-2xl font-semibold text-foreground">Bulk User Upload</h1>
              <p className="text-muted-foreground">Upload CSV file to create multiple user accounts at once</p>
            </div>
          </div>

          <div className="grid gap-6">
            <Card>
              <CardHeader>
                <CardTitle>CSV File Format</CardTitle>
                <CardDescription>Your CSV file should have the following format:</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="bg-muted p-4 rounded-md font-mono text-sm mb-4">
                  <div>email,name,role</div>
                  <div>user1@example.com,John Doe,developer</div>
                  <div>user2@example.com,Jane Smith,user</div>
                </div>
                <Alert>
                  <AlertCircle className="h-4 w-4" />
                  <AlertDescription>
                    <ul className="list-disc ml-4 space-y-1">
                      <li>First row should contain headers: email, name, role</li>
                      <li>Email addresses must be unique and valid</li>
                      <li>Role must be one of: admin, developer, user, guest</li>
                      <li>Users will receive welcome emails with temporary passwords</li>
                      <li>Users must change their password on first login</li>
                    </ul>
                  </AlertDescription>
                </Alert>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Upload CSV File</CardTitle>
                <CardDescription>Select a CSV file to upload</CardDescription>
              </CardHeader>
              <CardContent>
                <Form {...form}>
                  <form onSubmit={form.handleSubmit(handleSubmit)} className="space-y-4">
                    <FormField
                      control={form.control}
                      name="file"
                      render={({ field: { onChange, value, ...field } }) => (
                        <FormItem>
                          <FormLabel>CSV File</FormLabel>
                          <FormControl>
                            <Input
                              type="file"
                              accept=".csv"
                              onChange={(e) => onChange(e.target.files)}
                              {...field}
                              data-testid="input-csv-file"
                            />
                          </FormControl>
                          <FormDescription>
                            Upload a CSV file with user information
                          </FormDescription>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                    <Button 
                      type="submit" 
                      disabled={uploadMutation.isPending}
                      data-testid="button-upload"
                    >
                      {uploadMutation.isPending ? (
                        <>Uploading...</>
                      ) : (
                        <>
                          <Upload className="mr-2 h-4 w-4" />
                          Upload CSV
                        </>
                      )}
                    </Button>
                  </form>
                </Form>
              </CardContent>
            </Card>

            {uploadResult && (
              <Card>
                <CardHeader>
                  <CardTitle>Upload Results</CardTitle>
                  <CardDescription>
                    {uploadResult.success.length} successful, {uploadResult.failures.length} failed
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  {uploadResult.success.length > 0 && (
                    <div>
                      <h3 className="text-lg font-semibold mb-3 flex items-center">
                        <CheckCircle2 className="h-5 w-5 text-green-600 mr-2" />
                        Successfully Created ({uploadResult.success.length})
                      </h3>
                      <div className="border rounded-md">
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead>Email</TableHead>
                              <TableHead>Name</TableHead>
                              <TableHead>Temporary Password</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {uploadResult.success.map((user: { email: string; name: string; defaultPassword: string }, idx: number) => (
                              <TableRow key={idx} data-testid={`row-success-${idx}`}>
                                <TableCell data-testid={`text-email-${idx}`}>{user.email}</TableCell>
                                <TableCell data-testid={`text-name-${idx}`}>{user.name}</TableCell>
                                <TableCell className="font-mono" data-testid={`text-password-${idx}`}>
                                  {user.defaultPassword}
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </div>
                    </div>
                  )}

                  {uploadResult.failures.length > 0 && (
                    <div>
                      <h3 className="text-lg font-semibold mb-3 flex items-center">
                        <XCircle className="h-5 w-5 text-red-600 mr-2" />
                        Failed ({uploadResult.failures.length})
                      </h3>
                      <div className="border rounded-md">
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead>Email</TableHead>
                              <TableHead>Name</TableHead>
                              <TableHead>Reason</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {uploadResult.failures.map((user: { email: string; name: string; reason: string }, idx: number) => (
                              <TableRow key={idx} data-testid={`row-failure-${idx}`}>
                                <TableCell data-testid={`text-failure-email-${idx}`}>{user.email}</TableCell>
                                <TableCell data-testid={`text-failure-name-${idx}`}>{user.name}</TableCell>
                                <TableCell className="text-red-600" data-testid={`text-failure-reason-${idx}`}>
                                  {user.reason}
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
