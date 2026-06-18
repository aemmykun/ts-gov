// Postgres persistence layer — concrete implementations of the governance
// interfaces backed by the canonical schema.sql. The in-memory reference stores
// remain the default; these are opt-in for production / integration use.
export { PgContext, toVectorLiteral } from './pg'
export type { TenantContext, PgContextOptions } from './pg'
export { applySchema, defaultSchemaPath } from './migrate'
export { PostgresAssignmentResolver } from './PostgresAssignmentResolver'
export { PostgresTopicPolicyProvider } from './PostgresTopicPolicyProvider'
export { PostgresGovernancePolicyProvider } from './PostgresGovernancePolicyProvider'
export { PostgresLedgerStore } from './PostgresLedgerStore'
export { PostgresLedgerLock } from './PostgresLedgerLock'
export { PostgresVectorIndex } from './PostgresVectorIndex'
export { PostgresAuditLockService } from './PostgresAuditLockService'
export { PostgresAuthorityStore } from './PostgresAuthorityStore'
export type { AuthoritySnapshotRecord, DarDecisionRecord } from './PostgresAuthorityStore'
export { PostgresPolicyVersionStore } from './PostgresPolicyVersionStore'
export type { PolicyVersionRecord } from './PostgresPolicyVersionStore'
export { PostgresHandoffStore } from './PostgresHandoffStore'
