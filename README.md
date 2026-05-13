# Basic Auth Client Credentials Authorizer for OCI API Gateway

OCI API Gateway and many downstream Oracle integrations are easiest to protect with OAuth scopes. Some clients, however, cannot perform an OAuth client credentials flow themselves. They may only be able to send a Basic Authorization header containing a client ID and client secret.

> **Important:** This repository contains sample code that demonstrates how to use Basic Authentication with client credentials to call Oracle Integration Cloud through OCI API Gateway and an OCI Functions custom authorizer. This pattern is intended for corner-case scenarios where clients cannot perform a standard OAuth client credentials flow. It should not be used as the default approach when OAuth can be supported directly. Review, test, and adapt the code for your own environment, security requirements, operational standards, and compliance guidelines before using it in production.

> **Important:** This sample is not a general recommendation to replace OAuth with Basic Authentication. Use it only when you have a justified compatibility constraint and appropriate compensating controls.

This OCI Function handles that corner case. It acts as a custom authorizer for OCI API Gateway:

- accepts Basic credentials from the incoming request
- validates those credentials against an OCI Identity Domain token endpoint
- discovers the confidential app's allowed scopes
- returns one business scope to API Gateway for route authorization
- generates a downstream bearer token for the integration/resource call

## Flow

1. API Gateway invokes this function as a custom authorizer.
2. `handler()` loads function configuration from `ctx.Config()`.
3. `initContext()` initializes the Identity Domain settings:
   - identity domain base URL
   - admin app client ID
   - admin app client secret from OCI Vault
4. `read_auth_token()` reads the incoming Basic Authorization value from the payload or headers.
5. `extract_basic_auth()` decodes `client_id:client_secret`.
6. `get_client_scopes()` validates the caller credentials and resolves scopes.
7. `get_access_token()` requests a bootstrap/admin token using the caller credentials.
8. `decode_jwt_payload()` reads the `client_guid` claim from that token.
9. `fetch_app_by_client_guid()` uses the admin app credentials to read the caller app's allowed scopes.
10. `classify_scope()` separates:
    - the first business scope used by API Gateway route restrictions
    - the full `consumer::all` scope used to request the downstream token
11. `handler()` returns an authorizer response containing:
    - `active`
    - `scope`
    - `token`
    - `context.token`

## Authorizer Response

Successful response shape:

```json
{
  "active": true,
  "scope": "oic_api_HR",
  "token": "Bearer <access-token>",
  "context": {
    "token": "Bearer <access-token>"
  }
}
```

In this branch, the `scope` field is a single business scope string, not a list. If the confidential app has multiple business scopes, this version returns the first matching scope found by the code.

## Configuration

Configure these values on the deployed OCI Function.

```yaml
config:
  identity_domain_base_url: "https://<identity-domain>.identity.oraclecloud.com"
  client_id: "<admin-app-client-id>"
  secret_ocid: "<vault-secret-ocid-containing-admin-client-secret>"
```

### `identity_domain_base_url`

Base URL of the OCI Identity Domain used for token requests and app lookups.

### `client_id`

Client ID of the admin/confidential app that is allowed to query Identity Domain app details.

### `secret_ocid`

OCI Vault secret OCID containing the admin app client secret. The function reads this using resource principal authentication.

## Business Scope Behavior

This branch identifies business scopes by looking for the hardcoded prefix:

```text
oic_api_
```

For example, if the confidential app has an allowed scope like:

```text
oic_api_HR
```

the function returns:

```json
"scope": "oic_api_HR"
```

If you need configurable prefixes or multiple returned business scopes, use the feature branch that supports a business scope list.

## Cache Behavior

This branch keeps resolved scope data in an in-memory Python dictionary inside the warm OCI Function container.

- default cache TTL: 900 seconds
- cache location: OCI Function container memory
- not API Gateway cache
- cleared on cold start or new container

API Gateway may also cache authorizer results independently from this function's internal cache.

## Notes

- The full `consumer::all` scope is used only to request the downstream bearer token.
- The function expects OCI resource principal permissions to read the configured Vault secret.
- Review logging behavior before production use and avoid exposing secrets or full scope URLs in logs.
