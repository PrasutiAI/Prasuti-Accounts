/**
 * Utility functions for safely appending JWT tokens to URLs for allowed domains
 */

import { validateRedirectUrl, type DomainPattern } from './domain-validation';

export interface TokenUrlOptions {
  accessToken?: string;
  refreshToken?: string;
  includeRefreshToken?: boolean; // Default false for security
}

/**
 * Appends JWT tokens to a URL if the domain is allowed
 * @param url - The URL to potentially append tokens to
 * @param allowedDomains - Array of allowed domain patterns
 * @param tokens - Token options including access and refresh tokens
 * @returns Modified URL with tokens if domain is allowed, original URL otherwise
 */
export function appendTokensToUrl(
  url: string,
  allowedDomains: DomainPattern[],
  tokens: TokenUrlOptions
): string {
  // Validate that the URL is allowed
  const validation = validateRedirectUrl(url, allowedDomains);
  if (!validation.isValid || !validation.normalizedUrl) {
    return url; // Return original URL if not valid
  }

  try {
    const urlObj = new URL(validation.normalizedUrl);
    
    // Get existing query parameters
    const queryParams = new URLSearchParams(urlObj.search);

    // Add access token to query parameters
    if (tokens.accessToken) {
      queryParams.set('access_token', tokens.accessToken);
    }

    // Add refresh token only if explicitly requested and provided
    if (tokens.includeRefreshToken && tokens.refreshToken) {
      queryParams.set('refresh_token', tokens.refreshToken);
    }

    // Update URL with query parameters
    urlObj.search = queryParams.toString();

    return urlObj.toString();
  } catch (error) {
    // If URL manipulation fails, return original URL
    return url;
  }
}

/**
 * Checks if a URL should receive tokens based on domain validation
 * @param url - The URL to check
 * @param allowedDomains - Array of allowed domain patterns
 * @returns boolean indicating if tokens should be appended
 */
export function shouldAppendTokens(url: string, allowedDomains: DomainPattern[]): boolean {
  const validation = validateRedirectUrl(url, allowedDomains);
  return validation.isValid;
}