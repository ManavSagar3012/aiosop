# Keycloak for AI-OSOP multi-tenancy

Layered on top of the Step-E code (JWT claim extraction in `api/deps.py`).

## Bring-up

```sh
# 1. Secrets (never commit real values)
kubectl -n keycloak create secret generic keycloak-admin \
  --from-literal=username=admin --from-literal=password="$(openssl rand -base64 24)"
kubectl -n keycloak create secret generic keycloak-db \
  --from-literal=url="jdbc:postgresql://postgres:5432/keycloak" \
  --from-literal=username=keycloak --from-literal=password="$(openssl rand -base64 24)"

# 2. Deploy realm
kubectl apply -f k8s/keycloak/

# 3. Point the API at the realm
#    OSOP_JWT_SECRET=<realm RS256 public key>: paste realm public key from
#    http://keycloak:8080/realms/ai-osop after bootstrap into .env
#    OSOP_JWT_ISSUER=https://keycloak.ai-osop.internal/realms/ai-osop
#    OSOP_JWT_AUDIENCE=ai-osop-api

# 4. Smoke test
TOKEN=$(curl -s -X POST \
  "http://keycloak.ai-osop.internal/realms/ai-osop/protocol/openid-connect/token" \
  -d client_id=ai-osop-api -d client_secret="$KC_SECRET" \
  -d grant_type=client_credentials | jq -r .access_token)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8200/engagements
```

## Claim mapping

Every user must have a `tenant_id` (or legacy `org_id`) attribute set in Keycloak;
the realm's two protocol mappers copy it into the issued access token. Tokens
without either claim resolve to tenant `default` — kept as-is for migration.
To enforce isolation, set `OSOP_STRICT_TENANCY=true`.
