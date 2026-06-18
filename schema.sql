-- TenantSage — canonical governed-retrieval data model (source of truth).
-- The TypeScript governance library in src/ mirrors this schema:
--   tenant_id → family_id → child_id → user_id
--   topic-based policy (policies.allowed_topics ↔ rag_chunks.topic_key)
--   roles staff < supervisor < manager < admin
--   chunk status ACTIVE / REVOKED / EXPIRED
--   evidence_ledger decision ALLOW / DENY with a tamper-evident hash chain
-- Where the TS model and this schema differ, this schema takes precedence.
--
-- Tenant isolation is enforced FIRST in the relational model (the primary
-- control), with application-level filtering (the TS layer) as a secondary
-- control:
--   * Composite primary keys  (tenant_id, id)
--   * Composite foreign keys  that carry tenant_id along every edge of the
--     tenant → family → child → evidence chain (MATCH SIMPLE, so a NULL
--     family_id/child_id denotes tenant-global / family-level evidence)
--   * Row-Level Security      keyed on app.tenant_id / app.family_id /
--     app.child_id session GUCs, FORCEd so even table owners are constrained.

create extension if not exists pgcrypto;
create extension if not exists vector;

-- ── Composite boundary chain: tenant → family → child ───────────────────────

create table if not exists families (
  tenant_id uuid not null,
  id uuid not null default gen_random_uuid(),
  name text not null,
  owner_user_id uuid,
  created_at timestamptz not null default now(),
  primary key (tenant_id, id)
);

create table if not exists children (
  tenant_id uuid not null,
  id uuid not null default gen_random_uuid(),
  family_id uuid not null,
  label text not null,
  created_at timestamptz not null default now(),
  primary key (tenant_id, id),
  foreign key (tenant_id, family_id) references families(tenant_id, id)
);

-- Users are global identities (an external subject may be assigned into more
-- than one tenant); tenant scoping is carried on user_assignments below.
create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  external_subject text not null unique,
  display_name text not null,
  created_at timestamptz not null default now()
);

create table if not exists user_assignments (
  tenant_id uuid not null,
  id uuid not null default gen_random_uuid(),
  user_id uuid not null references users(id),
  family_id uuid not null,
  child_id uuid,
  role text not null check (role in ('staff', 'supervisor', 'manager', 'admin')),
  started_at timestamptz not null default now(),
  ended_at timestamptz,
  primary key (tenant_id, id),
  foreign key (tenant_id, family_id) references families(tenant_id, id),
  foreign key (tenant_id, child_id)  references children(tenant_id, id)
);

create unique index if not exists uq_active_user_assignment
  on user_assignments(tenant_id, user_id, child_id)
  where ended_at is null;

-- ── Topic-based policy + retention ──────────────────────────────────────────

create table if not exists policies (
  tenant_id uuid not null,
  id uuid not null default gen_random_uuid(),
  role text not null,
  allowed_topics text[] not null default '{}',
  version text not null,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  primary key (tenant_id, id)
);

create table if not exists retention_policies (
  tenant_id uuid not null,
  id uuid not null default gen_random_uuid(),
  resource_type text not null,
  valid_to timestamptz,
  active boolean not null default true,
  primary key (tenant_id, id)
);

-- ── Governed evidence: sources → chunks ─────────────────────────────────────

create table if not exists rag_sources (
  tenant_id uuid not null,
  id uuid not null default gen_random_uuid(),
  family_id uuid,
  child_id uuid,
  source_type text not null,
  source_uri text not null,
  classification text not null check (classification in ('public', 'internal', 'confidential', 'restricted')),
  retention_policy_id uuid not null,
  legal_hold boolean not null,
  valid_from timestamptz not null,
  valid_to timestamptz,
  created_at timestamptz not null default now(),
  primary key (tenant_id, id),
  foreign key (tenant_id, family_id)           references families(tenant_id, id),
  foreign key (tenant_id, child_id)            references children(tenant_id, id),
  foreign key (tenant_id, retention_policy_id) references retention_policies(tenant_id, id)
);

create table if not exists rag_chunks (
  tenant_id uuid not null,
  id uuid not null default gen_random_uuid(),
  source_id uuid not null,
  family_id uuid,
  child_id uuid,
  topic_key text not null,
  status text not null default 'ACTIVE' check (status in ('ACTIVE', 'REVOKED', 'EXPIRED')),
  legal_hold boolean not null default false,
  valid_from timestamptz not null,
  valid_to timestamptz,
  chunk_text text not null,
  metadata jsonb not null default '{}'::jsonb,
  embedding vector(3) not null,
  created_at timestamptz not null default now(),
  primary key (tenant_id, id),
  foreign key (tenant_id, source_id) references rag_sources(tenant_id, id),
  foreign key (tenant_id, family_id) references families(tenant_id, id),
  foreign key (tenant_id, child_id)  references children(tenant_id, id)
);

create index if not exists idx_rag_chunks_scope
  on rag_chunks(tenant_id, family_id, child_id, topic_key, status, legal_hold);

-- ── Evidence ledger (append-only, hash-chained) ─────────────────────────────

create table if not exists evidence_ledger (
  tenant_id uuid not null,
  id uuid not null default gen_random_uuid(),
  request_id uuid not null,
  decision text not null check (decision in ('ALLOW', 'DENY')),
  dar_decision_hash text not null,
  retrieved_evidence_ids uuid[] not null default array[]::uuid[],
  prompt_hash text,
  response_hash text,
  previous_hash text,
  current_hash text not null,
  data_json jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  primary key (tenant_id, id)
);

-- ── Row-Level Security (primary tenant-isolation control) ───────────────────
-- Session GUCs the application MUST set per request (fail-closed: an unset GUC
-- reads as NULL, so the predicates below filter every row out):
--   SET app.tenant_id = '<uuid>';      -- required
--   SET app.family_id = '<uuid>';      -- optional; null ⇒ all families in tenant
--   SET app.child_id  = '<uuid>';      -- optional; null ⇒ all children in scope

alter table families         enable row level security;
alter table children         enable row level security;
alter table users            enable row level security;
alter table user_assignments enable row level security;
alter table policies         enable row level security;
alter table retention_policies enable row level security;
alter table rag_sources      enable row level security;
alter table rag_chunks       enable row level security;
alter table evidence_ledger  enable row level security;

alter table families         force row level security;
alter table children         force row level security;
alter table users            force row level security;
alter table user_assignments force row level security;
alter table policies         force row level security;
alter table retention_policies force row level security;
alter table rag_sources      force row level security;
alter table rag_chunks       force row level security;
alter table evidence_ledger  force row level security;

-- Plain tenant isolation: row.tenant_id must equal the request's app.tenant_id.
create policy families_tenant_isolation on families
  using (tenant_id = current_setting('app.tenant_id', true)::uuid)
  with check (tenant_id = current_setting('app.tenant_id', true)::uuid);

create policy children_tenant_isolation on children
  using (tenant_id = current_setting('app.tenant_id', true)::uuid)
  with check (tenant_id = current_setting('app.tenant_id', true)::uuid);

create policy user_assignments_tenant_isolation on user_assignments
  using (tenant_id = current_setting('app.tenant_id', true)::uuid)
  with check (tenant_id = current_setting('app.tenant_id', true)::uuid);

create policy policies_tenant_isolation on policies
  using (tenant_id = current_setting('app.tenant_id', true)::uuid)
  with check (tenant_id = current_setting('app.tenant_id', true)::uuid);

create policy retention_policies_tenant_isolation on retention_policies
  using (tenant_id = current_setting('app.tenant_id', true)::uuid)
  with check (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- Users are global identities; expose only those with an assignment in the
-- current tenant.
create policy users_tenant_isolation on users
  using (exists (
    select 1 from user_assignments ua
    where ua.user_id = users.id
      and ua.tenant_id = current_setting('app.tenant_id', true)::uuid
  ));

-- Evidence (sources + chunks) enforces the full composite boundary chain:
-- tenant, then family (null ⇒ tenant-global), then child (null ⇒ family-level).
create policy rag_sources_boundary_isolation on rag_sources
  using (
        tenant_id = current_setting('app.tenant_id', true)::uuid
    and (current_setting('app.family_id', true) is null
         or family_id is null
         or family_id = current_setting('app.family_id', true)::uuid)
    and (current_setting('app.child_id', true) is null
         or child_id is null
         or child_id = current_setting('app.child_id', true)::uuid)
  )
  with check (tenant_id = current_setting('app.tenant_id', true)::uuid);

create policy rag_chunks_boundary_isolation on rag_chunks
  using (
        tenant_id = current_setting('app.tenant_id', true)::uuid
    and (current_setting('app.family_id', true) is null
         or family_id is null
         or family_id = current_setting('app.family_id', true)::uuid)
    and (current_setting('app.child_id', true) is null
         or child_id is null
         or child_id = current_setting('app.child_id', true)::uuid)
  )
  with check (tenant_id = current_setting('app.tenant_id', true)::uuid);

create policy evidence_ledger_tenant_isolation on evidence_ledger
  using (tenant_id = current_setting('app.tenant_id', true)::uuid)
  with check (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- Canonical governed-retrieval enforcement point. No service, model, tool, or
-- application may bypass this function. Mirrored in TS as searchRagChunksAudited().
-- Runs UNDER the RLS policies above (composite PK/FK + RLS are the primary
-- control; this predicate is the secondary, application-level control):
-- SELECT id, source_id, chunk_text, metadata
-- FROM rag_chunks
-- WHERE tenant_id = :tenant_id
--   AND (:family_id IS NULL OR family_id = :family_id)
--   AND (:child_id IS NULL OR child_id = :child_id)
--   AND topic_key = ANY(:eligible_topics)
--   AND status = 'ACTIVE'
--   AND legal_hold = false
--   AND valid_from <= NOW()
--   AND (valid_to IS NULL OR valid_to > NOW())
-- ORDER BY embedding <=> :query_embedding
-- LIMIT 12;
