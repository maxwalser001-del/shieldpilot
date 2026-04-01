---
name: varlock
description: Secure environment variable management skill. Mandatory whenever handling secrets, API keys, credentials, tokens, or sensitive configuration. Ensures secrets never appear in terminal output, Claude context, logs, git commits, or error messages. Enforces .env.schema validation over direct .env access.
---

# Varlock Skill

## Purpose
Secure environment variable management so secrets never appear in:
1 Terminal output
2 Claude input or output context
3 Logs or traces
4 Git commits or diffs
5 Error messages

This skill is mandatory whenever handling secrets, API keys, credentials, tokens, or sensitive configuration.

## Trigger phrases
Activate this skill immediately if any of these appear in the task or files:
environment variables
secrets
.env
API key
credentials
token
stripe
webhook secret
private key
sensitive
Varlock

## Non negotiable rules
### Rule 1 Never echo secrets
Forbidden examples
echo $STRIPE_SECRET_KEY
printenv | grep KEY
cat .env
less .env

Allowed alternatives
varlock load --quiet && echo "Environment validated"
varlock load
cat .env.schema

### Rule 2 Never read .env directly
Do not open, read, print, diff, or inspect .env values.
Do not use any tool to read .env.
The only allowed file inspection is .env.schema because it contains no values.

### Rule 3 Never include secrets in commands
Forbidden examples
curl -H "Authorization: Bearer sk_live_xxx" ...

Allowed alternatives
curl -H "Authorization: Bearer $STRIPE_SECRET_KEY" ...
Better
varlock run -- curl -H "Authorization: Bearer $STRIPE_SECRET_KEY" ...

### Rule 4 Never leak secrets through debugging
When debugging configuration, verify presence and format without printing values.
Allowed
varlock load
varlock load 2>&1 | grep STRIPE

Forbidden
echo $SECRET
printenv
cat .env

### Rule 5 Never commit secrets
Ensure .env is in .gitignore.
Only .env.schema is committed.

## Required workflow for any secret related change
Step 1 Ensure .env.schema exists and contains all required variables with sensitivity annotation
Step 2 Validate environment using Varlock
Step 3 Run commands via varlock run so secrets stay masked
Step 4 Ensure no logs output secret values
Step 5 Add regression guardrails to prevent future leakage

## Standard schema requirements
Add these defaults at top of .env.schema for high security projects
@defaultSensitive=true
@defaultRequired=infer

Mark public values explicitly as sensitive=false, for example publishable keys.

## Stripe specific schema recommendations
STRIPE_SECRET_KEY must be sensitive and format checked
Type string startsWith sk_

STRIPE_PUBLISHABLE_KEY should be sensitive=false and format checked
Type string startsWith pk_

STRIPE_WEBHOOK_SECRET must be sensitive and format checked
Type string startsWith whsec_

## Safe command patterns
Validate environment
varlock load
varlock load --quiet

Run app with secrets injected but not printed
varlock run -- npm start
varlock run -- python -m uvicorn ...

View schema safely
cat .env.schema
grep "^[A-Z]" .env.schema

## If user asks to show secrets
You must refuse.
Response format
I will not display secrets or read .env files.
Please update secrets manually outside this session.
I can help update .env.schema and validate with varlock load.

## Output requirements whenever this skill is active
Always include
1 What variables are required in schema
2 Which commands were used to validate environment
3 Confirmation that no secret values were printed
4 A check that .env is not committed and is gitignored
