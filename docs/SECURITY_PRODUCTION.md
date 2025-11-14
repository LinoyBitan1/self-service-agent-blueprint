# Production Security Configuration

This document identifies security settings that are safe for development but **MUST be changed for production**.

---

## 1. API Endpoints & Authentication

### JWT Authentication (Currently Disabled)
**Current State:** JWT authentication is disabled by default (`security.jwt.enabled: false`). Implementation is incomplete - signature verification is missing.

**Production Requirement:**
- **Do NOT enable JWT** - Use API Key authentication for production (recommended)

---

## 2. Service Boundaries & Network Security

### Kafka Security Configuration
**Current State:** Kafka uses `PLAINTEXT` protocol (no encryption, no authentication). Kafka is configured as internal only (`type: internal`).

**Security Risk:** NOT NECESSARILY a direct security issue for external attackers

**Production Requirement:**
Set secure Kafka configuration in `helm/values.yaml`:
```yaml
requestManagement:
  knative:
    kafka:
      security:
        protocol: "SASL_SSL"
        sasl:
          enabled: true
          mechanism: "SCRAM-SHA-512"
          user: "kafka-user"
          secretName: "kafka-credentials"
          secretKey: "password"
```
---

## 3. Secrets & Credentials Management

### API Keys and Secrets Rotation
**Current State:** Rotation should be planned for production.

**Production Requirement:**
- Implement API key rotation process (recommended: every 90 days or per security policy)
- Rotate API keys immediately if exposure is suspected or confirmed
- Document rotation process and maintain rotation schedule
- Store API keys in external secret manager with rotation support

---

## 4. Features That Should Be Disabled in Production

### Mock Eventing Service
**Current State:** Mock eventing is enabled by default (`requestManagement.knative.mockEventing.enabled: true`) for development. Real Knative eventing is disabled (`requestManagement.knative.eventing.enabled: false`).

**Production Requirement:**
**CRITICAL** - Disable mock eventing and enable real Knative eventing in `helm/values-production.yaml`:
```yaml
requestManagement:
  knative:
    eventing:
      enabled: true  # Enable real Knative eventing
    mockEventing:
      enabled: false  # Disable mock service
```

### Test Integration
**Current State:** Can be enabled via `testIntegrationEnabled: false` (disabled by default).

**Production Requirement:**
- Ensure `testIntegrationEnabled: false` in production values

---

## 5. Infrastructure & Deployment

### Image Tags
**Current State:** Default tag is `0.0.2` (specific version).

**Production Requirement:**
- Always use specific version tags (e.g., `v1.2.3`, `0.0.2`) - never use `latest` tag
- Update the tag to the latest stable version when deploying updates
- Ensure the tag matches the tested and approved image version
