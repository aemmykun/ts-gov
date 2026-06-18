import { readFileSync } from 'fs'
import { join } from 'path'
import { Pool } from 'pg'

// Resolves the canonical schema.sql at the repo root. Works under ts-jest/source
// execution (src/persistence → repo root); pass an explicit path for other
// layouts (e.g. compiled dist).
export function defaultSchemaPath(): string {
  return join(__dirname, '..', '..', 'schema.sql')
}

// Applies the canonical schema. schema.sql is fully idempotent (CREATE ... IF
// NOT EXISTS, CREATE POLICY guarded by caller), so this is safe to run on an
// empty database. Policies are created unconditionally, so this is intended for
// a fresh database (tests drop/recreate). Returns the SQL that was applied.
export async function applySchema(pool: Pool, schemaPath = defaultSchemaPath()): Promise<string> {
  const sql = readFileSync(schemaPath, 'utf8')
  await pool.query(sql)
  return sql
}
