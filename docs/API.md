# SentinelASM API

Generated from the OpenAPI schema of the running app (`make openapi` regenerates this file together with `docs/openapi.json`; the drift tests in `backend/tests/v3/test_openapi_docs.py` fail when either is stale).

Base URL: `/api/v1`. Every non-2xx uses the error envelope
`{"error": {"code", "message", "details"}}`. Auth: `Authorization: Bearer <access_token>`
or `X-API-Key: <key>`; `/auth/*` and `/health` need neither.

| Path | Method | Summary | Auth |
|------|--------|---------|------|
| `/api/v1/alerting/digest` | `DELETE` | Delete Digest Config | jwt or X-API-Key |
| `/api/v1/alerting/digest` | `GET` | Get Digest Config | jwt or X-API-Key |
| `/api/v1/alerting/digest` | `PATCH` | Update Digest Config | jwt or X-API-Key |
| `/api/v1/alerting/digest` | `POST` | Create Digest Config | jwt or X-API-Key |
| `/api/v1/alerting/digest/test` | `POST` | Test Digest Config | jwt or X-API-Key |
| `/api/v1/alerting/integrations` | `GET` | List Integrations | jwt or X-API-Key |
| `/api/v1/alerting/integrations` | `POST` | Create Integration | jwt or X-API-Key |
| `/api/v1/alerting/integrations/{integration_id}` | `DELETE` | Delete Integration | jwt or X-API-Key |
| `/api/v1/alerting/integrations/{integration_id}` | `GET` | Get Integration | jwt or X-API-Key |
| `/api/v1/alerting/integrations/{integration_id}` | `PATCH` | Update Integration | jwt or X-API-Key |
| `/api/v1/alerting/integrations/{integration_id}/test` | `POST` | Test Integration | jwt or X-API-Key |
| `/api/v1/alerts` | `GET` | List Alerts | jwt or X-API-Key |
| `/api/v1/assets` | `GET` | List Assets | jwt or X-API-Key |
| `/api/v1/assets/{asset_id}` | `GET` | Get Asset | jwt or X-API-Key |
| `/api/v1/assets/{asset_id}/enrich` | `POST` | Enrich Asset | jwt or X-API-Key |
| `/api/v1/assets/{asset_id}/graph` | `GET` | Get Asset Graph | jwt or X-API-Key |
| `/api/v1/audit-logs` | `GET` | List Audit Logs | jwt or X-API-Key |
| `/api/v1/auth/2fa/confirm` | `POST` | Confirm 2Fa | jwt or X-API-Key |
| `/api/v1/auth/2fa/disable` | `POST` | Disable 2Fa | jwt or X-API-Key |
| `/api/v1/auth/2fa/enroll` | `POST` | Enroll 2Fa | jwt or X-API-Key |
| `/api/v1/auth/2fa/regenerate-codes` | `POST` | Regenerate 2Fa Codes | jwt or X-API-Key |
| `/api/v1/auth/admin/reset-2fa` | `POST` | Admin Reset 2Fa | jwt or X-API-Key |
| `/api/v1/auth/admin/unlock-account` | `POST` | Admin Unlock Account | jwt or X-API-Key |
| `/api/v1/auth/change-password` | `POST` | Change Password | jwt or X-API-Key |
| `/api/v1/auth/forgot-password` | `POST` | Forgot Password | public |
| `/api/v1/auth/login` | `POST` | Login | public |
| `/api/v1/auth/login/2fa` | `POST` | Login 2Fa | jwt or X-API-Key |
| `/api/v1/auth/logout` | `POST` | Logout | jwt or X-API-Key |
| `/api/v1/auth/me` | `GET` | Me | jwt or X-API-Key |
| `/api/v1/auth/refresh` | `POST` | Refresh | public |
| `/api/v1/auth/register` | `POST` | Register | public |
| `/api/v1/auth/reset-password` | `POST` | Reset Password | public |
| `/api/v1/auth/step-up` | `POST` | Step Up | jwt or X-API-Key |
| `/api/v1/dashboard` | `GET` | Get Dashboard | jwt or X-API-Key |
| `/api/v1/findings` | `GET` | List Findings | jwt or X-API-Key |
| `/api/v1/findings/{finding_id}` | `GET` | Get Finding | jwt or X-API-Key |
| `/api/v1/organizations` | `POST` | Create Organization | jwt or X-API-Key |
| `/api/v1/organizations/2fa-requirement` | `POST` | Set 2Fa Requirement | jwt or X-API-Key |
| `/api/v1/organizations/api-keys` | `GET` | List Api Keys | jwt or X-API-Key |
| `/api/v1/organizations/api-keys` | `POST` | Create Api Key | jwt or X-API-Key |
| `/api/v1/organizations/api-keys/{key_id}` | `DELETE` | Delete Api Key | jwt or X-API-Key |
| `/api/v1/organizations/api-keys/{key_id}` | `PATCH` | Update Api Key | jwt or X-API-Key |
| `/api/v1/organizations/invitations` | `GET` | List Invitations | jwt or X-API-Key |
| `/api/v1/organizations/invitations` | `POST` | Create Invitation | jwt or X-API-Key |
| `/api/v1/organizations/invitations/{invitation_id}/revoke` | `POST` | Revoke Invitation | jwt or X-API-Key |
| `/api/v1/organizations/invitations/{token}/accept` | `POST` | Accept Invitation | jwt or X-API-Key |
| `/api/v1/organizations/me` | `GET` | Get My Organization | jwt or X-API-Key |
| `/api/v1/reports/export/all/csv` | `POST` | Export All Csv Endpoint | jwt or X-API-Key |
| `/api/v1/reports/export/assets/csv` | `POST` | Export Assets Csv Endpoint | jwt or X-API-Key |
| `/api/v1/reports/export/domains/csv` | `POST` | Export Domains Csv Endpoint | jwt or X-API-Key |
| `/api/v1/reports/export/findings/csv` | `POST` | Export Findings Csv Endpoint | jwt or X-API-Key |
| `/api/v1/reports/export/scans/csv` | `POST` | Export Scans Csv Endpoint | jwt or X-API-Key |
| `/api/v1/reports/pdf/executive-summary` | `GET` | Executive Summary Pdf | jwt or X-API-Key |
| `/api/v1/reports/pdf/finding/{finding_id}` | `GET` | Finding Detail Pdf | jwt or X-API-Key |
| `/api/v1/scan-policies` | `GET` | List Scan Policies | jwt or X-API-Key |
| `/api/v1/scan-policies` | `POST` | Create Scan Policy | jwt or X-API-Key |
| `/api/v1/scan-policies/{policy_id}` | `DELETE` | Delete Scan Policy | jwt or X-API-Key |
| `/api/v1/scan-policies/{policy_id}` | `GET` | Get Scan Policy | jwt or X-API-Key |
| `/api/v1/scan-policies/{policy_id}` | `PATCH` | Update Scan Policy | jwt or X-API-Key |
| `/api/v1/scan-policies/{policy_id}/run-now` | `POST` | Run Scan Policy Now | jwt or X-API-Key |
| `/api/v1/scans` | `GET` | List Scans | jwt or X-API-Key |
| `/api/v1/scans` | `POST` | Start Scan | jwt or X-API-Key |
| `/api/v1/scans/verified-domains` | `GET` | List Verified Domains | jwt or X-API-Key |
| `/api/v1/scans/verify-ownership` | `POST` | Request Ownership Verification | jwt or X-API-Key |
| `/api/v1/scans/verify-ownership/check` | `GET` | Check Ownership Verification | jwt or X-API-Key |
| `/api/v1/scans/{scan_id}` | `GET` | Get Scan Status | jwt or X-API-Key |
| `/health` | `GET` | Health | public |
| `/metrics` | `GET` | Metrics | public |

