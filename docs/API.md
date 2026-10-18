# SentinelASM API

Generated from the OpenAPI schema of the running app (`make openapi` regenerates this file together with `docs/openapi.json`; the drift tests in `backend/tests/v3/test_openapi_docs.py` fail when either is stale).

Base URL: `/api/v1`. Every non-2xx uses the error envelope
`{"error": {"code", "message", "details"}}`. Auth: `Authorization: Bearer <access_token>`
or `X-API-Key: <key>`; `/auth/*` and `/health` need neither.

| Path | Method | Summary | Auth |
|------|--------|---------|------|
| `/api/v1/alerting/digest` | `DELETE` | Delete Digest Config | public |
| `/api/v1/alerting/digest` | `GET` | Get Digest Config | public |
| `/api/v1/alerting/digest` | `PATCH` | Update Digest Config | public |
| `/api/v1/alerting/digest` | `POST` | Create Digest Config | public |
| `/api/v1/alerting/digest/test` | `POST` | Test Digest Config | public |
| `/api/v1/alerting/integrations` | `GET` | List Integrations | public |
| `/api/v1/alerting/integrations` | `POST` | Create Integration | public |
| `/api/v1/alerting/integrations/{integration_id}` | `DELETE` | Delete Integration | public |
| `/api/v1/alerting/integrations/{integration_id}` | `GET` | Get Integration | public |
| `/api/v1/alerting/integrations/{integration_id}` | `PATCH` | Update Integration | public |
| `/api/v1/alerting/integrations/{integration_id}/test` | `POST` | Test Integration | public |
| `/api/v1/alerts` | `GET` | List Alerts | public |
| `/api/v1/assets` | `GET` | List Assets | public |
| `/api/v1/assets/{asset_id}` | `GET` | Get Asset | public |
| `/api/v1/assets/{asset_id}/enrich` | `POST` | Enrich Asset | public |
| `/api/v1/assets/{asset_id}/graph` | `GET` | Get Asset Graph | public |
| `/api/v1/auth/2fa/confirm` | `POST` | Confirm 2Fa | public |
| `/api/v1/auth/2fa/disable` | `POST` | Disable 2Fa | public |
| `/api/v1/auth/2fa/enroll` | `POST` | Enroll 2Fa | public |
| `/api/v1/auth/2fa/regenerate-codes` | `POST` | Regenerate 2Fa Codes | public |
| `/api/v1/auth/admin/reset-2fa` | `POST` | Admin Reset 2Fa | public |
| `/api/v1/auth/admin/unlock-account` | `POST` | Admin Unlock Account | public |
| `/api/v1/auth/change-password` | `POST` | Change Password | public |
| `/api/v1/auth/forgot-password` | `POST` | Forgot Password | public |
| `/api/v1/auth/login` | `POST` | Login | public |
| `/api/v1/auth/login/2fa` | `POST` | Login 2Fa | public |
| `/api/v1/auth/logout` | `POST` | Logout | public |
| `/api/v1/auth/me` | `GET` | Me | public |
| `/api/v1/auth/refresh` | `POST` | Refresh | public |
| `/api/v1/auth/register` | `POST` | Register | public |
| `/api/v1/auth/reset-password` | `POST` | Reset Password | public |
| `/api/v1/dashboard` | `GET` | Get Dashboard | public |
| `/api/v1/findings` | `GET` | List Findings | public |
| `/api/v1/findings/{finding_id}` | `GET` | Get Finding | public |
| `/api/v1/organizations` | `POST` | Create Organization | public |
| `/api/v1/organizations/2fa-requirement` | `POST` | Set 2Fa Requirement | public |
| `/api/v1/organizations/api-keys` | `GET` | List Api Keys | public |
| `/api/v1/organizations/api-keys` | `POST` | Create Api Key | public |
| `/api/v1/organizations/api-keys/{key_id}` | `DELETE` | Delete Api Key | public |
| `/api/v1/organizations/api-keys/{key_id}` | `PATCH` | Update Api Key | public |
| `/api/v1/organizations/invitations` | `GET` | List Invitations | public |
| `/api/v1/organizations/invitations` | `POST` | Create Invitation | public |
| `/api/v1/organizations/invitations/{invitation_id}/revoke` | `POST` | Revoke Invitation | public |
| `/api/v1/organizations/invitations/{token}/accept` | `POST` | Accept Invitation | public |
| `/api/v1/organizations/me` | `GET` | Get My Organization | public |
| `/api/v1/reports/export/all/csv` | `POST` | Export All Csv Endpoint | public |
| `/api/v1/reports/export/assets/csv` | `POST` | Export Assets Csv Endpoint | public |
| `/api/v1/reports/export/domains/csv` | `POST` | Export Domains Csv Endpoint | public |
| `/api/v1/reports/export/findings/csv` | `POST` | Export Findings Csv Endpoint | public |
| `/api/v1/reports/export/scans/csv` | `POST` | Export Scans Csv Endpoint | public |
| `/api/v1/reports/pdf/executive-summary` | `GET` | Executive Summary Pdf | public |
| `/api/v1/reports/pdf/finding/{finding_id}` | `GET` | Finding Detail Pdf | public |
| `/api/v1/scan-policies` | `GET` | List Scan Policies | public |
| `/api/v1/scan-policies` | `POST` | Create Scan Policy | public |
| `/api/v1/scan-policies/{policy_id}` | `DELETE` | Delete Scan Policy | public |
| `/api/v1/scan-policies/{policy_id}` | `GET` | Get Scan Policy | public |
| `/api/v1/scan-policies/{policy_id}` | `PATCH` | Update Scan Policy | public |
| `/api/v1/scan-policies/{policy_id}/run-now` | `POST` | Run Scan Policy Now | public |
| `/api/v1/scans` | `GET` | List Scans | public |
| `/api/v1/scans` | `POST` | Start Scan | public |
| `/api/v1/scans/verified-domains` | `GET` | List Verified Domains | public |
| `/api/v1/scans/verify-ownership` | `POST` | Request Ownership Verification | public |
| `/api/v1/scans/verify-ownership/check` | `GET` | Check Ownership Verification | public |
| `/api/v1/scans/{scan_id}` | `GET` | Get Scan Status | public |
| `/health` | `GET` | Health | public |
| `/metrics` | `GET` | Metrics | public |

