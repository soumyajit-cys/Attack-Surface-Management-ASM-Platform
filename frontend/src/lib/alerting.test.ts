import { describe, expect, it } from 'vitest'

import { UNREADABLE_SECRET_MESSAGE, unreadableSecretBadge } from './alerting'

describe('unreadableSecretBadge', () => {
  it('shows the unreadable-secret badge for unreadable rows', () => {
    expect(unreadableSecretBadge({ secret_status: 'unreadable' })).toBe(
      UNREADABLE_SECRET_MESSAGE,
    )
    expect(UNREADABLE_SECRET_MESSAGE).toContain('SECRETS_ENCRYPTION_KEY')
  })

  it.each([['ok'], [undefined], [null], ['bogus']])(
    'shows no badge for secret_status=%s',
    (secret_status) => {
      expect(unreadableSecretBadge({ secret_status })).toBeNull()
    },
  )
})
