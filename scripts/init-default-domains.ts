import { storage } from "../server/storage";
import { insertAllowedDomainSchema } from "../shared/schema";

// Default allowed domains configuration
const defaultDomains = [
  {
    domain: "*.prasuti.ai",
    description: "Prasuti.ai wildcard domain - allows all subdomains of prasuti.ai",
    isActive: true,
  },
  {
    domain: "*.replit.dev",
    description: "Replit development domain - allows all subdomains of replit.dev",
    isActive: true,
  },
];

/**
 * Initialize default allowed domains for redirect URL validation
 * This function will create the default domains or update them if they already exist
 */
export async function initDefaultAllowedDomains() {
  console.log('Initializing default allowed domains...');
  
  for (const domainData of defaultDomains) {
    try {
      // Check if domain already exists
      const existingDomain = await storage.getAllowedDomainByDomain(domainData.domain);
      
      if (existingDomain) {
        console.log(`Domain '${domainData.domain}' already exists. Updating description...`);
        
        // Update description and active status if they've changed
        await storage.updateAllowedDomain(existingDomain.id, {
          description: domainData.description,
          isActive: domainData.isActive,
        });
        
        console.log(`✅ Updated domain '${domainData.domain}'`);
      } else {
        // Create new allowed domain
        const validatedDomain = insertAllowedDomainSchema.parse(domainData);
        const newDomain = await storage.createAllowedDomain(validatedDomain);
        
        console.log(`✅ Created allowed domain '${newDomain.domain}' - ${newDomain.description}`);
      }
    } catch (error) {
      console.error(`❌ Error processing domain '${domainData.domain}':`, error);
    }
  }
  
  console.log('✅ Default allowed domains initialization completed!');
}