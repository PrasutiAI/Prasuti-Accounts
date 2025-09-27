/**
 * Domain validation utilities for redirect URL security
 * Supports exact domain matching and wildcard patterns
 */

export interface DomainPattern {
  domain: string;
  isActive: boolean;
}

/**
 * Validates if a given URL matches allowed domain patterns
 * @param url - The URL to validate
 * @param allowedDomains - Array of allowed domain patterns
 * @returns boolean - true if URL is allowed, false otherwise
 */
export function isUrlAllowed(url: string, allowedDomains: DomainPattern[]): boolean {
  try {
    // Parse the URL to extract the hostname
    const parsedUrl = new URL(url);
    const hostname = parsedUrl.hostname.toLowerCase();
    
    // Filter only active domains
    const activeDomains = allowedDomains.filter(d => d.isActive);
    
    // Check against each allowed domain pattern
    return activeDomains.some(domainPattern => 
      matchesDomainPattern(hostname, domainPattern.domain.toLowerCase())
    );
  } catch (error) {
    // Invalid URL format
    return false;
  }
}

/**
 * Checks if a hostname matches a domain pattern
 * @param hostname - The hostname to check (e.g., "api.prasuti.ai")
 * @param pattern - The domain pattern (e.g., "*.prasuti.ai" or "www.google.com")
 * @returns boolean - true if hostname matches pattern
 */
export function matchesDomainPattern(hostname: string, pattern: string): boolean {
  // Exact match
  if (hostname === pattern) {
    return true;
  }
  
  // Wildcard pattern matching
  if (pattern.startsWith('*.')) {
    const baseDomain = pattern.substring(2); // Remove "*.""
    
    // Check if hostname ends with the base domain
    if (hostname.endsWith('.' + baseDomain)) {
      return true;
    }
    
    // Also allow exact match with base domain (e.g., "prasuti.ai" matches "*.prasuti.ai")
    if (hostname === baseDomain) {
      return true;
    }
  }
  
  return false;
}

/**
 * Validates a domain pattern format
 * @param pattern - The domain pattern to validate
 * @returns boolean - true if pattern is valid
 */
export function isValidDomainPattern(pattern: string): boolean {
  // Check for empty or invalid patterns
  if (!pattern || typeof pattern !== 'string') {
    return false;
  }
  
  const trimmedPattern = pattern.trim().toLowerCase();
  
  // Check for wildcard pattern
  if (trimmedPattern.startsWith('*.')) {
    const baseDomain = trimmedPattern.substring(2);
    return isValidDomainName(baseDomain);
  }
  
  // Check for exact domain
  return isValidDomainName(trimmedPattern);
}

/**
 * Validates if a string is a valid domain name
 * @param domain - The domain to validate
 * @returns boolean - true if domain is valid
 */
export function isValidDomainName(domain: string): boolean {
  // Basic domain name validation
  const domainRegex = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i;
  
  // Check length (max 253 characters for full domain)
  if (domain.length > 253) {
    return false;
  }
  
  // Check each label (part between dots) is max 63 characters
  const labels = domain.split('.');
  if (labels.some(label => label.length > 63)) {
    return false;
  }
  
  // Check against regex
  return domainRegex.test(domain);
}

/**
 * Normalizes a domain pattern for storage
 * @param pattern - The domain pattern to normalize
 * @returns string - normalized pattern
 */
export function normalizeDomainPattern(pattern: string): string {
  return pattern.trim().toLowerCase();
}

/**
 * Validates and normalizes a redirect URL
 * @param url - The URL to validate and normalize
 * @param allowedDomains - Array of allowed domain patterns
 * @returns { isValid: boolean, normalizedUrl?: string, error?: string }
 */
export function validateRedirectUrl(
  url: string, 
  allowedDomains: DomainPattern[]
): { isValid: boolean; normalizedUrl?: string; error?: string } {
  try {
    // Parse and normalize the URL
    const parsedUrl = new URL(url);
    
    // Only allow http and https protocols
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      return {
        isValid: false,
        error: 'Only HTTP and HTTPS protocols are allowed'
      };
    }
    
    // Check if domain is allowed
    if (!isUrlAllowed(url, allowedDomains)) {
      return {
        isValid: false,
        error: 'Domain not in allowed list'
      };
    }
    
    return {
      isValid: true,
      normalizedUrl: parsedUrl.toString()
    };
  } catch (error) {
    return {
      isValid: false,
      error: 'Invalid URL format'
    };
  }
}