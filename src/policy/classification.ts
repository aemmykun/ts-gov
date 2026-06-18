// Governance classification is a closed enum, never free text —
// 'Confidential' vs 'confidential' vs 'CONFIDENTIAL' must not become a
// governance bug. Matches the SQL `classification` check constraint.

export type Classification = 'public' | 'internal' | 'confidential' | 'restricted'

const CLASSIFICATION_ORDER: Classification[] = ['public', 'internal', 'confidential', 'restricted']

export function isClassification(v: unknown): v is Classification {
  return typeof v === 'string' && (CLASSIFICATION_ORDER as string[]).includes(v.toLowerCase())
}

// Returns true when `value` is at or below `ceiling`. Unknown/invalid values
// are treated as exceeding any ceiling (fail-closed).
export function classificationWithin(value: string | undefined, ceiling: Classification): boolean {
  if (!isClassification(value)) return false
  return CLASSIFICATION_ORDER.indexOf(value.toLowerCase() as Classification)
    <= CLASSIFICATION_ORDER.indexOf(ceiling)
}
