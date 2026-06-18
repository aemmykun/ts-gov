import { Role } from './roles'

export { Role }

// Identity attested by the SSO provider. Establishes *who* the caller is.
//
// IMPORTANT: a claim attests identity ONLY. It deliberately carries NO authority
// fields (no role / familyId / orgUnit). Authority — role, organisation, scope,
// family, clearance — is resolved exclusively from authoritative assignments via
// the DAR. Keeping authority out of the claim removes a whole class of
// `if (claim.role === 'admin')` privilege-escalation bugs by construction.
export interface TenantClaim {
  userId:     string
  tenantId:   string
  provider:   'entra' | 'okta'
  verifiedAt: number
}

export interface SSOConfig {
  entra: {
    jwksUri:  string
    clientId: string
    tenantId: string
  }
  okta: {
    jwksUri:  string
    clientId: string
    domain:   string
  }
}
