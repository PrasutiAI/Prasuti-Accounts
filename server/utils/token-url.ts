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
    const fragmentParams = new URLSearchParams();

    // Add access token to URL fragment if provided (more secure than query params)
    if (tokens.accessToken) {
      fragmentParams.set('access_token', tokens.accessToken);
    }

    // Add refresh token only if explicitly requested and provided
    if (tokens.includeRefreshToken && tokens.refreshToken) {
      fragmentParams.set('refresh_token', tokens.refreshToken);
    }

    // Only add fragment if we have tokens to add
    if (fragmentParams.toString()) {
      urlObj.hash = fragmentParams.toString();
    }

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