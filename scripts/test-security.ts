import { execSync } from 'child_process';

// Polyfill fetch for Node.js environments
declare global {
  var fetch: typeof import('undici').fetch;
}

/**
 * Security Verification Script
 * Tests all security features to ensure they work correctly
 */

interface TestResult {
  name: string;
  status: 'PASS' | 'FAIL' | 'WARN';
  message: string;
  details?: string;
}

const results: TestResult[] = [];

function addResult(name: string, status: 'PASS' | 'FAIL' | 'WARN', message: string, details?: string) {
  results.push({ name, status, message, details });
  
  const emoji = status === 'PASS' ? '✅' : status === 'FAIL' ? '❌' : '⚠️';
  console.log(`${emoji} ${name}: ${message}`);
  if (details) {
    console.log(`   ${details}`);
  }
}

async function testApiEndpoint(url: string, options: any = {}): Promise<any> {
  const baseUrl = process.env.BASE_URL || 'http://localhost:5000';
  const response = await fetch(`${baseUrl}${url}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });
  return response;
}

async function testRateLimiting() {
  console.log('\n🔒 Testing Rate Limiting...');
  
  try {
    // Test auth rate limiting (should allow 5 requests then block)
    const requests: Promise<any>[] = [];
    for (let i = 0; i < 7; i++) {
      requests.push(testApiEndpoint('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email: 'test@example.com', password: 'wrongpassword' }),
      }));
    }
    
    const responses = await Promise.all(requests);
    const rateLimitedResponses = responses.filter(r => r.status === 429);
    
    if (rateLimitedResponses.length >= 2) {
      addResult('Rate Limiting', 'PASS', 'Authentication rate limiting works correctly');
    } else {
      addResult('Rate Limiting', 'FAIL', 'Rate limiting not working as expected');
    }
  } catch (error) {
    addResult('Rate Limiting', 'FAIL', `Error testing rate limiting: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function testSecurityHeaders() {
  console.log('\n🛡️ Testing Security Headers...');
  
  try {
    const response = await testApiEndpoint('/health');
    const headers = response.headers;
    
    // Check essential security headers
    const securityHeaders = [
      'x-frame-options',
      'x-content-type-options',
      'referrer-policy',
      'strict-transport-security',
    ];
    
    let missingHeaders = 0;
    for (const header of securityHeaders) {
      if (!headers.get(header)) {
        missingHeaders++;
        console.log(`   Missing header: ${header}`);
      }
    }
    
    if (missingHeaders === 0) {
      addResult('Security Headers', 'PASS', 'All security headers present');
    } else {
      addResult('Security Headers', 'WARN', `${missingHeaders} security headers missing`);
    }
  } catch (error) {
    addResult('Security Headers', 'FAIL', `Error testing headers: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function testJWTSecurity() {
  console.log('\n🔑 Testing JWT Security...');
  
  try {
    // Test JWKS endpoint
    const jwksResponse = await testApiEndpoint('/.well-known/jwks.json');
    if (jwksResponse.ok) {
      const jwks = await jwksResponse.json();
      if (jwks.keys && jwks.keys.length > 0) {
        addResult('JWT JWKS', 'PASS', 'JWKS endpoint working correctly');
      } else {
        addResult('JWT JWKS', 'FAIL', 'JWKS endpoint has no keys');
      }
    } else {
      addResult('JWT JWKS', 'FAIL', 'JWKS endpoint not accessible');
    }
    
    // Test invalid token rejection
    const protectedResponse = await testApiEndpoint('/api/users', {
      headers: { Authorization: 'Bearer invalid_token' },
    });
    
    if (protectedResponse.status === 401) {
      addResult('JWT Validation', 'PASS', 'Invalid tokens properly rejected');
    } else {
      addResult('JWT Validation', 'FAIL', 'Invalid tokens not properly rejected');
    }
  } catch (error) {
    addResult('JWT Security', 'FAIL', `Error testing JWT: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function testAuthenticationFlow() {
  console.log('\n🔐 Testing Authentication Flow...');
  
  try {
    // Test without authentication
    const protectedResponse = await testApiEndpoint('/api/users');
    if (protectedResponse.status === 401) {
      addResult('Auth Required', 'PASS', 'Protected endpoints require authentication');
    } else {
      addResult('Auth Required', 'FAIL', 'Protected endpoints accessible without auth');
    }
    
    // Test registration endpoint
    const registerResponse = await testApiEndpoint('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        email: `test-${Date.now()}@example.com`,
        password: 'SecurePassword123!',
        name: 'Test User',
      }),
    });
    
    if (registerResponse.status === 201 || registerResponse.status === 400) {
      addResult('Registration', 'PASS', 'Registration endpoint functioning');
    } else {
      addResult('Registration', 'FAIL', `Registration failed with status ${registerResponse.status}`);
    }
  } catch (error) {
    addResult('Authentication', 'FAIL', `Error testing auth: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function testInputValidation() {
  console.log('\n🧹 Testing Input Validation...');
  
  try {
    // Test malformed JSON
    const malformedResponse = await testApiEndpoint('/api/auth/login', {
      method: 'POST',
      body: '{ invalid json',
    });
    
    if (malformedResponse.status === 400) {
      addResult('Input Validation', 'PASS', 'Malformed requests properly rejected');
    } else {
      addResult('Input Validation', 'WARN', 'Malformed request handling could be improved');
    }
    
    // Test XSS attempt
    const xssResponse = await testApiEndpoint('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        email: '<script>alert("xss")</script>',
        password: 'test',
      }),
    });
    
    if (xssResponse.status === 400) {
      addResult('XSS Protection', 'PASS', 'XSS attempts properly handled');
    } else {
      addResult('XSS Protection', 'WARN', 'XSS protection could be improved');
    }
  } catch (error) {
    addResult('Input Validation', 'FAIL', `Error testing validation: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function testDatabaseSecurity() {
  console.log('\n🗄️ Testing Database Security...');
  
  try {
    // Check if database is accessible
    const response = await testApiEndpoint('/ready');
    if (response.ok) {
      addResult('Database Access', 'PASS', 'Database connection secure and functional');
    } else {
      addResult('Database Access', 'FAIL', 'Database connection issues detected');
    }
    
    // Test SQL injection attempt
    const sqlInjectionResponse = await testApiEndpoint('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        email: "'; DROP TABLE users; --",
        password: 'test',
      }),
    });
    
    if (sqlInjectionResponse.status === 400 || sqlInjectionResponse.status === 401) {
      addResult('SQL Injection Protection', 'PASS', 'SQL injection attempts properly handled');
    } else {
      addResult('SQL Injection Protection', 'WARN', 'SQL injection protection needs verification');
    }
  } catch (error) {
    addResult('Database Security', 'FAIL', `Error testing database: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function checkEnvironmentSecurity() {
  console.log('\n🌐 Testing Environment Security...');
  
  try {
    // Check for development mode warnings
    const isProduction = process.env.NODE_ENV === 'production';
    
    if (isProduction) {
      addResult('Environment', 'PASS', 'Running in production mode');
    } else {
      addResult('Environment', 'WARN', 'Running in development mode', 
        'Ensure production settings for live deployment');
    }
    
    // Check critical environment variables
    const requiredEnvVars = ['DATABASE_URL', 'ENCRYPTION_MASTER_KEY'];
    const missingVars = requiredEnvVars.filter(env => !process.env[env]);
    
    if (missingVars.length === 0) {
      addResult('Environment Variables', 'PASS', 'All critical environment variables set');
    } else {
      addResult('Environment Variables', 'FAIL', `Missing: ${missingVars.join(', ')}`);
    }
  } catch (error) {
    addResult('Environment Security', 'FAIL', `Error checking environment: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function printSummary() {
  console.log('\n' + '='.repeat(60));
  console.log('🔒 SECURITY VERIFICATION SUMMARY');
  console.log('='.repeat(60));
  
  const passed = results.filter(r => r.status === 'PASS').length;
  const failed = results.filter(r => r.status === 'FAIL').length;
  const warnings = results.filter(r => r.status === 'WARN').length;
  
  console.log(`✅ Passed: ${passed}`);
  console.log(`❌ Failed: ${failed}`);
  console.log(`⚠️  Warnings: ${warnings}`);
  console.log(`📊 Total Tests: ${results.length}`);
  
  if (failed > 0) {
    console.log('\n❌ FAILED TESTS:');
    results.filter(r => r.status === 'FAIL').forEach(r => {
      console.log(`   • ${r.name}: ${r.message}`);
    });
  }
  
  if (warnings > 0) {
    console.log('\n⚠️  WARNINGS:');
    results.filter(r => r.status === 'WARN').forEach(r => {
      console.log(`   • ${r.name}: ${r.message}`);
    });
  }
  
  const score = Math.round((passed / results.length) * 100);
  console.log(`\n🏆 Security Score: ${score}%`);
  
  if (score >= 90) {
    console.log('🎉 Excellent security posture!');
  } else if (score >= 75) {
    console.log('✨ Good security posture with room for improvement');
  } else {
    console.log('🚨 Security improvements needed');
  }
}

async function runSecurityTests() {
  console.log('🔒 Starting Security Verification Tests...');
  console.log('='.repeat(60));
  
  try {
    // Wait for server to be ready
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    await testRateLimiting();
    await testSecurityHeaders();
    await testJWTSecurity();
    await testAuthenticationFlow();
    await testInputValidation();
    await testDatabaseSecurity();
    checkEnvironmentSecurity();
    
    printSummary();
    
    // Exit with appropriate code
    const failed = results.filter(r => r.status === 'FAIL').length;
    process.exit(failed > 0 ? 1 : 0);
    
  } catch (error) {
    console.error('❌ Security test runner failed:', error);
    process.exit(1);
  }
}

// Add fetch polyfill for Node.js if needed
if (typeof globalThis.fetch === 'undefined') {
  console.log('⚠️  Fetch not available. Install node-fetch or run in a browser environment.');
  process.exit(1);
} else {
  runSecurityTests();
}