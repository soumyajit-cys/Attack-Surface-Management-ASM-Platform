/**
 * Badge classes for scan and verification statuses.
 *
 * Pure helpers (no DOM) so they are unit-tested in statusBadges.test.ts.
 * Unknown statuses intentionally fall back to neutral gray.
 */

export function scanStatusBadgeClass(status: string): string {
  switch (status) {
    case 'completed':
      return 'text-success-600 bg-success-100'
    case 'running':
      return 'text-primary-600 bg-primary-100'
    case 'pending':
      return 'text-warning-600 bg-warning-100'
    case 'failed':
      return 'text-danger-600 bg-danger-100'
    case 'skipped':
      // Phase 1: scans gated by domain verification (unverified/expired).
      return 'text-amber-700 bg-amber-100'
    default:
      return 'text-gray-600 bg-gray-100'
  }
}

export function verificationBadgeClass(status: string): string {
  switch (status) {
    case 'verified':
      return 'text-success-600 bg-success-100'
    case 'pending':
      return 'text-warning-600 bg-warning-100'
    case 'grandfathered':
      // Grace-period row: scans run, but the owner must verify. Amber, and
      // the Scans page additionally shows the grace deadline. Never styled
      // as verified.
      return 'text-amber-700 bg-amber-100'
    case 'failed':
      return 'text-danger-600 bg-danger-100'
    default:
      // expired and anything unexpected render neutral.
      return 'text-gray-600 bg-gray-100'
  }
}
