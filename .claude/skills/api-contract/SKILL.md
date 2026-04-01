---
name: api-contract
description: API contract definition protocol for ShieldPilot Frontend and Backend agents. Use when defining a new API endpoint, agreeing on request and response formats, planning frontend-backend integration, or documenting API changes. Ensures Frontend api() calls match Backend FastAPI endpoints. Trigger phrases include API contract, endpoint definition, request format, response format, frontend backend agreement.
---

# ShieldPilot API Contract Protocol

Ensures Frontend and Backend agents agree on exact API contracts before implementation. Prevents integration mismatches.

## When to use

Before implementation when:
- Adding a new API endpoint
- Changing an existing endpoint's request or response format
- Adding new query parameters or changing auth requirements
- Adding or removing error responses

## ShieldPilot API conventions

### URL patterns
- All paths start with /api/
- Kebab-case segments: /api/auth/password-reset/request
- Resource IDs as path params: /api/commands/{command_id}
- Query params for filtering: ?page=1&limit=20&risk_level=high

### Authentication
- Most endpoints: Bearer token via Authorization header
- API key alternative: X-API-Key header
- Public endpoints (no auth): /api/health, /api/auth/login, /api/auth/register, /api/auth/password-reset/*, /api/auth/verify-email, /api/auth/google/*, /api/billing/webhook, /api/legal/impressum
- Admin-only: Depends(require_admin)
- Tier-gated: Depends(require_feature("feature_name"))

### Response conventions
- Success: JSON object
- 204 No Content: delete/void operations (frontend api() returns null)
- Error: HTTPException with {"error": "short", "message": "Human readable"}
- 401: Frontend auto-logout (api() clears token, redirects to /login)
- 429: Include Retry-After header

### Request conventions
- POST/PUT/PATCH: JSON body, Content-Type: application/json
- Pydantic models validate bodies
- Field(..., max_length=N) for string limits
- Optional fields: Optional[type] = None

### SSE (Server-Sent Events)
- StreamingResponse with media_type="text/event-stream"
- Format: data: {json}\n\n
- Token via query param (EventSource does not support headers)

## Contract template

For each new or modified endpoint:

```markdown
## API Contract: [Endpoint Name]

### Endpoint
- Method: GET / POST / PUT / PATCH / DELETE
- Path: /api/[path]
- Auth: None / Bearer / Admin / Feature gated ([feature])

### Path params
| Param | Type | Required | Description |
|-------|------|----------|-------------|

### Query params
| Param | Type | Default | Description |
|-------|------|---------|-------------|

### Request body (Pydantic model)
```python
class CreateItemRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=256)
    description: Optional[str] = None
```

### Success response (200)
```json
{
    "id": 1,
    "title": "Example",
    "created_at": "2026-02-11T12:00:00"
}
```

### Error responses
| Status | Condition | Detail |
|--------|-----------|--------|
| 400 | Invalid input | {"error": "Invalid input", "message": "..."} |
| 401 | No/invalid token | {"error": "Authentication required"} |
| 403 | Wrong tier | {"error": "Feature not available", "tier": "free"} |
| 404 | Not found | {"error": "Item not found"} |
| 429 | Rate limited | {"error": "Too many requests", "message": "..."} |

### Rate limiting
- Limiter: [name] / None
- Max: N per M seconds
- Key: IP / email / user_id

### Frontend integration
```javascript
const data = await api('/api/items', { params: { page: 1 } });
const result = await api('/api/items', { method: 'POST', body: { title } });
await api(`/api/items/${id}`, { method: 'DELETE' });
```
```

## Validation checklists

### Backend checks
- [ ] Endpoint path matches contract
- [ ] HTTP method matches contract
- [ ] Pydantic model matches contract fields and types
- [ ] Response JSON matches contract structure
- [ ] All error codes and detail formats match
- [ ] Auth dependency matches (get_current_user / require_admin / none)
- [ ] Rate limiter configured as specified
- [ ] Super-admin bypass where needed

### Frontend checks
- [ ] api() call uses correct path
- [ ] api() call uses correct HTTP method
- [ ] Request body keys match Pydantic field names
- [ ] Response fields accessed match contract
- [ ] 401 auto-logout handled by api() (no extra code)
- [ ] 204 No Content handled (api() returns null)
- [ ] Error states: EmptyState() or showToast()
- [ ] Loading state: Spinner()
- [ ] All dynamic response data via escapeHtml()

### Integration checks
- [ ] Query param names match Backend Query() names
- [ ] Request body keys match Pydantic field names (camelCase vs snake_case)
- [ ] Pagination consistent (page/limit)
- [ ] Date formats consistent (ISO 8601)

## Existing endpoints reference

Current API surface:

```
Auth:
  POST /api/auth/login              -> Token
  POST /api/auth/register           -> Token
  POST /api/auth/password-reset/*   -> status
  GET  /api/auth/verify-email       -> redirect
  POST /api/auth/verify-email/resend -> resend verification [Depends(get_current_user)]
  GET  /api/auth/google             -> redirect
  GET  /api/auth/google/callback    -> redirect + token
  GET  /api/auth/me                 -> user profile

Settings:
  GET  /api/settings                -> user settings
  POST /api/settings/password       -> change password
  POST /api/settings/username       -> change username
  DELETE /api/settings/account      -> delete account
  POST /api/settings/api-key        -> generate key
  DELETE /api/settings/api-key      -> revoke key

Dashboard:
  GET  /api/health                  -> health check
  GET  /api/health/chain            -> audit chain integrity
  GET  /api/usage                   -> UsageInfo
  GET  /api/stats                   -> dashboard statistics
  GET  /api/stats/stream            -> SSE real-time stats
  GET  /api/activity/stream         -> SSE real-time activity

Data:
  GET  /api/commands                -> paginated command log
  GET  /api/commands/{id}           -> command detail
  GET  /api/incidents               -> incident list
  PATCH /api/incidents/{id}/resolve -> resolve incident
  GET  /api/scans                   -> scan history
  POST /api/scan/prompt             -> run prompt scan
  GET  /api/activity/feed           -> activity feed
  GET  /api/config/summary          -> config overview

Export:
  GET  /api/export/commands         -> CSV/JSON
  GET  /api/export/incidents        -> CSV/JSON

Library:
  GET  /api/library                 -> public items
  GET  /api/library/admin           -> admin view
  GET  /api/library/categories       -> category list [Depends(require_verified_email)]
  GET  /api/library/topics          -> topic tree
  POST /api/library/topics          -> create topic
  PATCH /api/library/topics/reorder -> reorder
  PUT  /api/library/topics/{id}     -> update topic
  DELETE /api/library/topics/{id}   -> delete topic
  GET  /api/library/{id}            -> single item
  POST /api/library                 -> create item
  PUT  /api/library/{id}            -> update item
  DELETE /api/library/{id}          -> delete item

Billing:
  GET  /api/billing/pricing         -> tier info [Depends(get_current_user)]
  GET  /api/billing/tier            -> current tier and features [Depends(get_current_user)]
  POST /api/billing/checkout        -> Stripe session
  POST /api/billing/portal          -> Stripe portal
  POST /api/billing/webhook         -> Stripe webhook (public)

Admin:
  POST /api/admin/users/tier        -> set user tier
  POST /api/admin/reconcile-subscriptions -> reconcile
  GET  /api/admin/stripe-health     -> Stripe status

Legal:
  GET  /api/legal/impressum         -> legal info
  GET  /api/account/export          -> GDPR export
```

## Output

Add completed contracts to the feature spec as a section titled "## API Contract" in `/features/PROJ-X-feature-name.md`.
