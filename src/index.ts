// Identity
export * from './identity/types'
export * from './identity/roles'
export { SSOGate } from './identity/SSOGate'
export { TenantIsolationGuard } from './identity/TenantIsolationGuard'

// Authoritative assignments
export * from './assignments/types'
export { InMemoryAssignmentResolver } from './assignments/InMemoryAssignmentResolver'

// Policy
export * from './policy/types'
export * from './policy/classification'
export {
  TopicPolicy,
  TopicPolicyProvider,
  InMemoryTopicPolicyProvider,
} from './policy/TopicPolicyProvider'
export { PolicyEngine } from './policy/PolicyEngine'
export { AuditLockService } from './policy/AuditLockService'
export { TenantBoundaryCheck } from './policy/checks/TenantBoundaryCheck'
export { ScopeCheck } from './policy/checks/ScopeCheck'
export { TopicPermissionCheck } from './policy/checks/TopicPermissionCheck'
export { StatusCheck } from './policy/checks/StatusCheck'
export { RetentionCheck } from './policy/checks/RetentionCheck'
export { LegalHoldCheck } from './policy/checks/LegalHoldCheck'
export { EffectiveDateCheck } from './policy/checks/EffectiveDateCheck'
export {
  SourceGovernance,
  GovernancePolicyProvider,
  IngestionGovernanceBinder,
  MissingGovernancePolicyError,
  PolicyIntegrityError,
  computePolicyChecksum,
} from './policy/GovernancePolicyProvider'

// DAR
export { DAREngine, DARConfig } from './dar/DAREngine'
export * from './dar/types'
export { scopeMatches } from './dar/scope'

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
export { LedgerLock, InProcessLedgerLock } from './ledger/LedgerLock'
export { AuditLockSink } from './policy/AuditLockService'

// Canonical runtime pipeline
export * from './TenantSagePipeline'

// Postgres persistence layer (opt-in; backed by schema.sql)
export * from './persistence'
