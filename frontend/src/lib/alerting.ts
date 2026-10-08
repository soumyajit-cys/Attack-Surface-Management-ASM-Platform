/**
 * Alert-integration credential helpers (Phase 1, task 1.4).
 *
 * Pure helpers (no DOM) so they are unit-tested in alerting.test.ts.
 * The API never returns full secret values: rows carry `secret_status`
 * ("ok" | "unreadable"), `has_webhook_url`, and `webhook_url_masked`.
 */

export const UNREADABLE_SECRET_MESSAGE =
  'unreadable secret: check SECRETS_ENCRYPTION_KEY'

export interface SecretStatusRow {
  secret_status?: string | null
}

/** Badge text for an integration whose stored secret cannot be decrypted. */
export function unreadableSecretBadge(integration: SecretStatusRow): string | null {
  if (integration.secret_status === 'unreadable') {
    return UNREADABLE_SECRET_MESSAGE
  }
  return null
}
