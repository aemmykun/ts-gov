-- TenantSage — canonical governed-retrieval data model (source of truth).
-- The TypeScript governance library in src/ mirrors this schema:
--   tenant_id → family_id → child_id → user_id
--   topic-based policy (policies.allowed_topics ↔ rag_chunks.topic_key)
--   roles staff < supervisor < manager < admin
--   chunk status ACTIVE / REVOKED / EXPIRED
--   evidence_ledger decision ALLOW / DENY with a tamper-evident hash chain
-- Where the TS model and this schema differ, this schema takes precedence.

create extension if not exists pgcrypto;
create extension if not exists vector;

create table if not exists families (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  owner_user_id uuid,
  created_at timestamptz not null default now()
);

create table if not exists children (
  id uuid primary key default gen_random_uuid(),
  family_id uuid not null references families(id),
  label text not null,
  created_at timestamptz not null default now()
);

create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  external_subject text not null unique,
  display_name text not null,
  created_at timestamptz not null default now()
);

create table if not exists user_assignments (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id),
  family_id uuid not null references families(id),
  child_id uuid references children(id),
  role text not null check (role in ('staff', 'supervisor', 'manager', 'admin')),
  started_at timestamptz not null default now(),
  ended_at timestamptz
);

create unique index if not exists uq_active_user_assignment
  on user_assignments(user_id, child_id)
  where ended_at is null;

create table if not exists policies (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  role text not null,
  allowed_topics text[] not null default '{}',
  version text not null,
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists retention_policies (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  resource_type text not null,
  valid_to timestamptz,
  active boolean not null default true
);

create table if not exists rag_sources (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  family_id uuid references families(id),
  child_id uuid references children(id),
  source_type text not null,
  source_uri text not null,
  classification text not null check (classification in ('public', 'internal', 'confidential', 'restricted')),
  retention_policy_id uuid not null references retention_policies(id),
  legal_hold boolean not null,
  valid_from timestamptz not null,
  valid_to timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists rag_chunks (
  id uuid primary key default gen_random_uuid(),
  source_id uuid not null references rag_sources(id),
  tenant_id uuid not null,
  family_id uuid references families(id),
  child_id uuid references children(id),
  topic_key text not null,
  status text not null default 'ACTIVE' check (status in ('ACTIVE', 'REVOKED', 'EXPIRED')),
  legal_hold boolean not null default false,
  valid_from timestamptz not null,
  valid_to timestamptz,
  chunk_text text not null,
  metadata jsonb not null default '{}'::jsonb,
  embedding vector(3) not null,
  created_at timestamptz not null default now()
);

create index if not exists idx_rag_chunks_scope
  on rag_chunks(tenant_id, family_id, child_id, topic_key, status, legal_hold);

create table if not exists evidence_ledger (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null,
  tenant_id uuid not null,
  decision text not null check (decision in ('ALLOW', 'DENY')),
  dar_decision_hash text not null,
  retrieved_evidence_ids uuid[] not null default array[]::uuid[],
  prompt_hash text,
  response_hash text,
  previous_hash text,
  current_hash text not null,
  data_json jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

alter table families enable row level security;
alter table children enable row level security;
alter table users enable row level security;
alter table user_assignments enable row level security;
alter table policies enable row level security;
alter table retention_policies enable row level security;
alter table rag_sources enable row level security;
alter table rag_chunks enable row level security;
alter table evidence_ledger enable row level security;

-- Canonical governed-retrieval enforcement point. No service, model, tool, or
-- application may bypass this function. Mirrored in TS as searchRagChunksAudited().
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
