# ShieldPilot Billing — Stripe Setup Guide

## Overview

ShieldPilot uses Stripe for subscription billing. Users can upgrade from **Free** to **Pro** ($19.99/month) to unlock:

- Full Prompts & Skills library
- Unlimited scans (vs. 10/day on Free)
- 1000 commands/day (vs. 50 on Free)
- 30-day blocked activity history (vs. 1 day)
- AI-powered analysis
- Data export
- API access

## Architecture

```
User clicks "Upgrade" → Stripe Checkout → Payment → Webhook → DB tier updated → Features unlocked
```

| Component | File |
|-----------|------|
| Stripe Client | `sentinelai/billing/stripe_stub.py` |
| Webhook Handler | `sentinelai/api/routes.py` (stripe_webhook) |
| Tier Resolution | `sentinelai/api/deps.py` (get_user_tier_limits) |
| User Model | `sentinelai/logger/database.py` (User) |
| Pricing Page | `sentinelai/web/static/js/app.js` (renderPricing) |
| Paywall Modal | `sentinelai/web/static/js/components.js` (showPaywallModal) |

## Tier System

| Tier | How Set | Limits |
|------|---------|--------|
| `free` | Default for new users | 50 cmd/day, 10 scans/day, 1-day history |
| `pro` | Stripe webhook after checkout | 1000 cmd/day, 100 scans/day, 30-day history |
| `enterprise` | Manual or Stripe | Unlimited |
| `unlimited` | Super-admin only | Bypasses everything |

Tier resolution priority: `super-admin > user.tier from DB > config.billing.tier (fallback)`

## Local Development Setup

### Prerequisites

- Python 3.10+
- ShieldPilot running locally (`python3 -m sentinelai.api.app`)
- Stripe account (free to create)

### Step-by-Step

#### 1. Create Stripe Account

Go to https://dashboard.stripe.com/register and create an account.

#### 2. Create a Product + Price

1. Go to https://dashboard.stripe.com/test/products
2. Click **"Add product"**
3. Fill in:
   - **Name:** ShieldPilot Pro
   - **Description:** Unlimited scans, full library, 30-day history
4. Under **Pricing:**
   - **Model:** Standard pricing
   - **Price:** 19.99
   - **Currency:** EUR
   - **Billing period:** Monthly (recurring)
5. Click **Save product**
6. Copy the **Price ID** (starts with `price_...`)

#### 3. Get API Keys

1. Go to https://dashboard.stripe.com/test/apikeys
2. Copy:
   - **Publishable key:** `pk_test_...`
   - **Secret key:** `sk_test_...`

#### 4. Set Environment Variables

```bash
export STRIPE_SECRET_KEY=sk_test_...
export STRIPE_PUBLISHABLE_KEY=pk_test_...
export STRIPE_PRICE_PRO_MONTHLY=price_...
```

Or add to your `.env` file.

#### 5. Install Stripe CLI (for webhook testing)

```bash
brew install stripe/stripe-cli/stripe
```

#### 6. Login to Stripe CLI

```bash
stripe login
```

#### 7. Forward Webhooks to Local Server

```bash
stripe listen --forward-to http://127.0.0.1:8420/api/billing/webhook
```

Copy the **webhook signing secret** from the output (starts with `whsec_...`):

```bash
export STRIPE_WEBHOOK_SECRET=whsec_...
```

#### 8. Start ShieldPilot

```bash
python3 -m sentinelai.api.app
```

#### 9. Test the Flow

1. Open http://localhost:8420/login
2. Login as a free user
3. Navigate to **#/pricing**
4. Click **"Upgrade to Pro"**
5. Use test card: `4242 4242 4242 4242` (any future date, any CVC)
6. Complete checkout
7. Verify redirect back to pricing page with success banner

#### 10. Verify in Database

```bash
sqlite3 sentinel.db "SELECT email, tier, stripe_customer_id, stripe_subscription_id, subscription_status FROM users WHERE tier='pro';"
```

## Webhook Events

| Event | Handler | Action |
|-------|---------|--------|
| `checkout.session.completed` | `_handle_checkout_completed` | Set tier=pro, store sub ID/status/period |
| `customer.subscription.updated` | `_handle_subscription_updated` | Update tier + status + period_end |
| `customer.subscription.deleted` | `_handle_subscription_deleted` | Set tier=free, clear sub fields |
| `invoice.paid` | `_handle_invoice_paid` | Confirm status=active, restore tier |
| `invoice.payment_failed` | `_handle_invoice_failed` | Set status=past_due |

## Test Cards

| Card Number | Scenario |
|-------------|----------|
| `4242 4242 4242 4242` | Success |
| `4000 0000 0000 3220` | 3D Secure required |
| `4000 0000 0000 9995` | Payment fails |
| `4000 0000 0000 0341` | Attaches but first charge fails |

## Cancellation

Users can cancel via the **Manage Subscription** button on the pricing page, which opens the Stripe Customer Portal.

When a subscription is canceled:
1. Stripe sends `customer.subscription.deleted` webhook
2. User's tier is set back to `free`
3. Subscription fields are cleared

## Production Checklist

- [ ] Switch from test keys (`sk_test_`) to live keys (`sk_live_`)
- [ ] Set up production webhook endpoint in Stripe Dashboard
- [ ] Configure webhook events: checkout.session.completed, customer.subscription.updated, customer.subscription.deleted, invoice.paid, invoice.payment_failed
- [ ] Set `STRIPE_WEBHOOK_SECRET` to production webhook secret
- [ ] Update `app_base_url` in sentinel.yaml to production URL
- [ ] Verify HTTPS is enabled (Stripe requires it for production)
- [ ] Test with real card (low amount)
- [ ] Set up Stripe email receipts
