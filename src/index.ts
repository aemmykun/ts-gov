// Identity
export * from './identity/types'
export * from './identity/roles'
export { SSOGate } from './identity/SSOGate'
export { TenantIsolationGuard } from './identity/TenantIsolationGuard'

// Authoritative assignments (correction #1)
export * from './assignments/types'
export { InMemoryAssignmentResolver } from './assignments/InMemoryAssignmentResolver'

// Policy (corrections #2/#3 inputs)
export * from './policy/types'
export { PolicyEngine } from './policy/PolicyEngine'
export { AuditLockService } from './policy/AuditLockService'
export { RetentionCheck } from './policy/checks/RetentionCheck'
export { LegalHoldCheck } from './policy/checks/LegalHoldCheck'
export { RolePermissionCheck } from './policy/checks/RolePermissionCheck'
export { EffectiveDateCheck } from './policy/checks/EffectiveDateCheck'
export {
  GovernancePolicyProvider,
  IngestionGovernanceBinder,
  MissingGovernancePolicyError,
} from './policy/GovernancePolicyProvider'

// DAR (correction #1)
export { DAREngine } from './dar/DAREngine'
export * from './dar/types'

// TrustRAG governed retrieval (correction #5)
export { TrustRAGRetriever, UnauthorizedRetrievalError } from './trustrag/TrustRAGRetriever'
export * from './trustrag/types'

// Approved evidence corpus (correction #3)
export * from './runtime/ApprovedEvidenceCorpus'

// HandOff evidence integrity (correction #4)
export * from './handoff/types'
export { HandOffBuilder } from './handoff/HandOffBuilder'
export { HandOffVerifier } from './handoff/HandOffVerifier'
export * from './handoff/HandOffSigner'

// Evidence ledger
export * from './ledger/types'
export { BlockBuilder } from './ledger/BlockBuilder'
export { EvidenceLedger } from './ledger/EvidenceLedger'
export { ChainVerifier } from './ledger/ChainVerifier'
export { ReplayEngine } from './ledger/ReplayEngine'
export { LedgerStore, InMemoryLedgerStore } from './ledger/LedgerStore'

// Canonical runtime pipeline
export * from './TenantSagePipeline'
