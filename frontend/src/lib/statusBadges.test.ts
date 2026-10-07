import { describe, expect, it } from 'vitest'

import { scanStatusBadgeClass, verificationBadgeClass } from './statusBadges'

describe('scanStatusBadgeClass', () => {
  it.each([
    ['completed', 'text-success-600 bg-success-100'],
    ['running', 'text-primary-600 bg-primary-100'],
    ['pending', 'text-warning-600 bg-warning-100'],
    ['failed', 'text-danger-600 bg-danger-100'],
    // Phase 1 gated-but-not-run scans render distinctly from failures.
    ['skipped', 'text-amber-700 bg-amber-100'],
    ['retrying', 'text-gray-600 bg-gray-100'],
    ['bogus', 'text-gray-600 bg-gray-100'],
  ])('maps %s to %s', (status, expected) => {
    expect(scanStatusBadgeClass(status)).toBe(expected)
  })
})

describe('verificationBadgeClass', () => {
  it.each([
    ['verified', 'text-success-600 bg-success-100'],
    ['pending', 'text-warning-600 bg-warning-100'],
    // Grandfathered grace rows must never look verified.
    ['grandfathered', 'text-amber-700 bg-amber-100'],
    ['failed', 'text-danger-600 bg-danger-100'],
    ['expired', 'text-gray-600 bg-gray-100'],
    ['bogus', 'text-gray-600 bg-gray-100'],
  ])('maps %s to %s', (status, expected) => {
    expect(verificationBadgeClass(status)).toBe(expected)
  })

  it('never styles grandfathered as verified', () => {
    expect(verificationBadgeClass('grandfathered')).not.toBe(
      verificationBadgeClass('verified')
    )
  })
})
