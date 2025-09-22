import { QueryClient, QueryFunction } from "@tanstack/react-query";

async function throwIfResNotOk(res: Response) {
  if (!res.ok) {
    // Read response as text first to avoid body stream consumption issues
    const responseText = await res.text();
    
    try {
      // Try to parse the text as JSON for proper error messages
      const errorData = JSON.parse(responseText);
      const message = errorData.message || errorData.error || res.statusText;
      throw new Error(message);
    } catch (jsonError) {
      // If JSON parsing fails, use the text content or status text as fallback
      const fallbackMessage = responseText || res.statusText;
      throw new Error(`${res.status}: ${fallbackMessage}`);
    }
  }
}

export async function apiRequest(
  method: string,
  url: string,
  data?: unknown | undefined,
): Promise<Response> {
  const res = await fetch(url, {
    method,
    headers: data ? { "Content-Type": "application/json" } : {},
    body: data ? JSON.stringify(data) : undefined,
    credentials: "include",
  });

  // Clone the response before error checking to preserve the body for the caller
  await throwIfResNotOk(res.clone());
  return res;
}

type UnauthorizedBehavior = "returnNull" | "throw";
export const getQueryFn: <T>(options: {
  on401: UnauthorizedBehavior;
}) => QueryFunction<T> =
  ({ on401: unauthorizedBehavior }) =>
  async ({ queryKey }) => {
    const res = await fetch(queryKey.join("/") as string, {
      credentials: "include",
    });

    if (unauthorizedBehavior === "returnNull" && res.status === 401) {
      return null;
    }

    // Clone the response before error checking to preserve the body for JSON parsing
    await throwIfResNotOk(res.clone());
    return await res.json();
  };

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      queryFn: getQueryFn({ on401: "throw" }),
      refetchInterval: false,
      refetchOnWindowFocus: false,
      staleTime: Infinity,
      retry: false,
    },
    mutations: {
      retry: false,
    },
  },
});
