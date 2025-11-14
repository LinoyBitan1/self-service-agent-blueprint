# Security Action Items

---

| # | Issue | Security Issue? | Section |
|---|-------|----------------|---------|
| 1 | Generic endpoint `/api/v1/requests/generic` without authentication | YES | [Generic Endpoint Without Authentication](#generic-endpoint-without-authentication) |
| 2 | Health check `/health` endpoint without authentication | NO | [Health Check Endpoints](#health-check-endpoints) |
| 3 | Health check `/health/detailed` endpoint exposes service information | MAYBE | [Health Check Endpoints](#health-check-endpoints) |
| 4 | CloudEvents endpoint `/api/v1/events/cloudevents` without authentication | YES | [CloudEvents Endpoint Without Authentication](#cloudevents-endpoint-without-authentication) |
| 5 | Missing network policies for critical services | NO | [Missing Network Policies for Critical Services](#missing-network-policies-for-critical-services) |
| 6 | No secret rotation mechanism | MAYBE | [No Secret Rotation Mechanism](#no-secret-rotation-mechanism) |
| 7 | CLI access uses unauthenticated endpoint | YES | [CLI Access Uses Unauthenticated Endpoint](#cli-access-uses-unauthenticated-endpoint) |
| 8 | Information leakage via logging (INFO/WARNING/DEBUG levels) | MAYBE | [Information Leakage via Logging](#information-leakage-via-logging-infowarningdebug-levels) |

---

## 1. API Endpoints & Authentication

#### Generic Endpoint Without Authentication

- **Risk:** YES
- **Options:**
  1. Add `Depends(get_current_user)` dependency (same as `/api/v1/requests/web` and `/api/v1/requests/cli`)
  2. Remove endpoint if unused (check usage in `shared-clients/src/shared_clients/request_manager_client.py`)

#### Health Check Endpoints Without Authentication

**`/health` Endpoint:**
- **Risk:** NO
- Lightweight operation, no database access


#### health/detailed Endpoint Without Authentication
**`/health/detailed` Endpoint :**
- **Risk:** MAYBE
- Performs database queries and returns service information (version, database status, integrations list) without authentication

#### CloudEvents Endpoint Without Authentication

- **Risk:** YES
- May this endpoint should be internal only
- Potential for unauthorized event injection if exposed externally

---

## 2. Service Boundaries & Network Security

#### Missing Network Policies for Critical Services
**Issue:** Request-manager and integration-dispatcher have no network policies defined.

-**Risk:** NO
-This is not a security risk because network policies protect against attackers who already have OpenShift/cluster access

---

## 3. Secrets & Credentials Management

#### No Secret Rotation Mechanism
**Issue:** No automated secret rotation process documented or implemented.

- **Risk:** Long-lived secrets increase exposure risk like ServiceNow API KEY
- **Action:**
  - Document rotation process
  - Implement automation (External Secrets Operator with rotation)
  - Add monitoring/alerting for expiration

---

## 4. Features That Should Be Disabled in Production

#### CLI Access Uses Unauthenticated Endpoint

**Issue:** CLI client uses unauthenticated `/api/v1/requests/generic` endpoint. Request Manager external access disabled by default (`externalAccess.enabled: false`).

**Options:**
1. **Disable CLI in production** (recommended)
   - Keep `externalAccess.enabled: false`

2. **Fix CLI authentication**
   - Change line 226: `endpoint="generic"` to `endpoint="cli"`
   - Fix `endpoint="generic"`

#### Information Leakage via Logging (INFO/WARNING Levels)
**Issue:** Multiple services log sensitive information (PII, request/response bodies) at INFO/WARNING levels active in production.

**Risk:** NOT NECESSARILY a security issue for external attackers

1. **ServiceNow Client - Full Request/Response Body Logging**
   - **File:** `mcp-servers/snow/src/snow/servicenow/client.py` lines 125, 134, 142
   - **Issue:** Logs complete request body, response body, and full response at INFO level

2. **Agent Service - Full Response Logging**
   - **File:** `agent-service/src/agent_service/session_manager.py` line 645
   - **Issue:** Logs complete agent response (`processed_response`) at INFO level

3. **Slack Service - Full User Info Logging**
   - **File:** `integration-dispatcher/src/integration_dispatcher/slack_service.py` line 619
   - **Issue:** Logs complete `user_info` object at WARNING level

4. **Request Manager - Integration Context Logging**
   - **File:** `request-manager/src/request_manager/main.py` line 933
   - **Issue:** Logs complete `integration_context` with `slack_user_id`, `slack_channel`, `email_from`
