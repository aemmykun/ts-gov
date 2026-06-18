import { Role } from './roles'

export { Role }

// Identity attested by the SSO provider. Establishes *who* the caller is.
// IMPORTANT: a claim attests identity only. It is NOT a source of retrieval
// authority — authority is resolved from authoritative assignments (see DAR).
export interface TenantClaim {
  userId:     string
  tenantId:   string
  familyId:   string
  role:       Role
  orgUnit:    string
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
