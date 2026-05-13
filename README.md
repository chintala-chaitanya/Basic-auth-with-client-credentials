# Basic Auth Client Credentials Authorizer for OCI API Gateway

OCI API Gateway and many downstream Oracle integrations are easiest to protect with OAuth scopes. Some clients, however, cannot perform an OAuth client credentials flow themselves. They may only be able to send a Basic Authorization header containing a client ID and client secret.

> **Important:** This repository contains sample code that demonstrates how to use Basic Authentication with client credentials to call Oracle Integration Cloud through OCI API Gateway and an OCI Functions custom authorizer. This pattern is intended for corner-case scenarios where clients cannot perform a standard OAuth client credentials flow. It should not be used as the default approach when OAuth can be supported directly. Review, test, and adapt the code for your own environment, security requirements, operational standards, and compliance guidelines before using it in production.

> **Important:** This sample is not a general recommendation to replace OAuth with Basic Authentication. Use it only when you have a justified compatibility constraint and appropriate compensating controls.

This OCI Function handles that corner case. It acts as a custom authorizer for OCI API Gateway:

- accepts Basic credentials from the incoming request
- validates those credentials against an OCI Identity Domain token endpoint
- discovers the confidential app's allowed scopes
- returns the business scopes to API Gateway for route authorization
- generates a downstream bearer token for the integration/resource call

## Flow

1. API Gateway invokes this function as a custom authorizer.
2. `handler()` loads function configuration from `ctx.Config()`.
3. `initContext()` initializes the Identity Domain settings:
   - identity domain base URL
   - admin app client ID
   - admin app client secret from OCI Vault
   - business scope prefix
   - scope cache TTL
4. `read_auth_token()` reads the incoming Basic Authorization value from the payload or headers.
5. `extract_basic_auth()` decodes `client_id:client_secret`.
6. `get_client_scopes()` validates the caller credentials and resolves scopes.
7. `get_access_token()` requests a bootstrap/admin token using the caller credentials.
8. `decode_jwt_payload()` reads the `client_guid` claim from that token.
9. `fetch_app_by_client_guid()` uses the admin app credentials to read the caller app's allowed scopes.
10. `classify_scope()` separates:
    - business scopes used by API Gateway route restrictions
    - full `consumer::all` scope used to request the downstream token
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
  "scope": ["oic_api_HR", "oic_api_IT"],
  "token": "Bearer <access-token>",
  "context": {
    "token": "Bearer <access-token>"
  }
}
```

The `scope` field is a list of business scopes. This branch supports multiple route-restriction scopes, so a single client app can authorize routes that require any matching scope from the returned list. OCI API Gateway can use these values for route-level scope checks.

## Configuration

Configure these values on the deployed OCI Function.

```yaml
config:
  identity_domain_base_url: "https://<identity-domain>.identity.oraclecloud.com"
  client_id: "<admin-app-client-id>"
  secret_ocid: "<vault-secret-ocid-containing-admin-client-secret>"
  business_scope_prefix: "oic_api_"
  scope_cache_ttl: "900"
```

### `identity_domain_base_url`

Base URL of the OCI Identity Domain used for token requests and app lookups.

### `client_id`

Client ID of the admin/confidential app that is allowed to query Identity Domain app details.

### `secret_ocid`

OCI Vault secret OCID containing the admin app client secret. The function reads this using resource principal authentication.

### `business_scope_prefix`

Prefix used to identify scopes that should be returned to API Gateway as business scopes.

Example:

```yaml
business_scope_prefix: "oic_api_"
```

If the confidential app has allowed scopes such as:

```text
oic_api_HR
oic_api_IT
```

the function returns:

```json
"scope": ["oic_api_HR", "oic_api_IT"]
```

This is configurable because different teams may use different naming conventions for route-restriction scopes.

### `scope_cache_ttl`

Controls in-memory caching of resolved client scopes inside the warm function container.

- `0`: disable scope caching, useful for testing
- `900`: cache for 15 minutes, useful for production
- any positive integer: cache for that many seconds

This cache is not API Gateway cache. It is a Python dictionary inside the running OCI Function container. It survives only while that container stays warm.

For testing scope changes on a confidential app, use:

```yaml
scope_cache_ttl: "0"
```

For production, a non-zero value reduces Identity Domain API calls.

## Notes

- The full `consumer::all` scope is used only to request the downstream bearer token.
- Business scopes are logged in masked form.
- Full consumer scopes are logged in masked form.
- API Gateway may also cache authorizer results independently from this function's internal scope cache.
- The function expects OCI resource principal permissions to read the configured Vault secret.
