// Governance classification & sensitivity are closed enums, never free text —
// 'Confidential' vs 'confidential' vs 'CONFIDENTIAL' must not become a
// governance bug. Comparisons are tier-ordered and case-insensitive on input.

export type Classification = 'public' | 'internal' | 'confidential' | 'restricted'
export type Sensitivity    = 'low' | 'medium' | 'high' | 'critical'

const CLASSIFICATION_ORDER: Classification[] = ['public', 'internal', 'confidential', 'restricted']
const SENSITIVITY_ORDER:    Sensitivity[]    = ['low', 'medium', 'high', 'critical']

export function isClassification(v: unknown): v is Classification {
  return typeof v === 'string' && (CLASSIFICATION_ORDER as string[]).includes(v.toLowerCase())
}

export function isSensitivity(v: unknown): v is Sensitivity {
  return typeof v === 'string' && (SENSITIVITY_ORDER as string[]).includes(v.toLowerCase())
}

// Returns true when `value` is at or below `ceiling`. Unknown/invalid values
// are treated as exceeding any ceiling (fail-closed).
export function classificationWithin(value: string | undefined, ceiling: Classification): boolean {
  if (!isClassification(value)) return false
  return CLASSIFICATION_ORDER.indexOf(value.toLowerCase() as Classification)
    <= CLASSIFICATION_ORDER.indexOf(ceiling)
}

export function sensitivityWithin(value: string | undefined, ceiling: Sensitivity): boolean {
  if (!isSensitivity(value)) return false
  return SENSITIVITY_ORDER.indexOf(value.toLowerCase() as Sensitivity)
    <= SENSITIVITY_ORDER.indexOf(ceiling)
}
