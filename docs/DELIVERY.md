# Alert delivery

Alert delivery uses the durable PostgreSQL outbox. `OUTBOX_ENQUEUE_ENABLED` and
`OUTBOX_DELIVERY_ENABLED` both default to `false`; enabling delivery requires selecting a channel,
configuring the owner mapping, a security recipient, and that channel's transport credentials.
Configuration belongs in a secret store or local `.env`; never commit live webhook URLs or SMTP
credentials.

The configured owner map resolves the alert owner to an email address or a Teams route reference.
P1/P2 alerts also create a separate security route in the same transaction as alert persistence.
For email, `OUTBOX_SECURITY_RECIPIENT_REF` must be a mailbox address. For Teams, the message route is
sent to the separately configured security workflow webhook. P3/P4 alerts only use the owner route.

Email delivery uses SMTP with STARTTLS. SMTP username and password must be configured together.
Teams delivery posts a JSON `text` message to a Microsoft Teams Workflows webhook; configure the
workflow URL separately for owner and security routes. The webhook URL is a credential and must be
protected as a secret. Configure the workflow trigger for its secret-URL authentication mode
(`Anyone`); tenant-token authentication is not implemented by this adapter. Microsoft documents the Workflows webhook request flow in
[Create an Incoming Webhook](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook).

The worker claims one message at a time with a database lease. Every claim and result is recorded in
the append-only audit chain. Known pre-send connection rejection, Teams HTTP 429, or SMTP 4xx
responses receive bounded exponential retries. A timeout, lost connection after sending, Teams 5xx
response, or expired delivery lease is marked `unknown` and is not automatically resent because the
remote service may already have accepted the message. No replay action is exposed yet; check the
destination before a controlled administrative replay.
Permanent provider rejection becomes `failed`; accepted messages become `delivered`.

`GET /api/v1/deliveries` is available to the operator and admin roles. It supports status, channel,
run, and pagination filters. Daily digest entries have no run ID and expose only their digest date,
UTC window, and alert count. The API returns hashed recipient references and safe provider response
categories; it never returns raw recipient addresses or stored message payloads. Request filters and
delivery attempts are audited.

## Daily digest

Set `OUTBOX_DAILY_DIGEST_ENABLED=true` to schedule the previous complete UTC day at
`OUTBOX_DAILY_DIGEST_HOUR_UTC` and `OUTBOX_DAILY_DIGEST_MINUTE_UTC` (defaults to 09:00 UTC).
Digests are grouped by configured owner recipient, with an additional P1/P2 security digest. The
per-message item limit is controlled by `OUTBOX_DAILY_DIGEST_MAX_ITEMS`; omitted alert counts are
reported in the message. If the worker starts after the configured delivery time, it queues the
previous UTC day to recover that window after a restart. A unique idempotency key makes concurrent
scheduler instances safe. Digest creation
requires outbox enqueue and delivery to be enabled, and actual external sends remain governed by
the same approval and credential gates as individual alerts.
Every scheduled evaluation writes a chained audit event with the UTC window, eligible/mapped alert
counts, candidate message count, and enqueued versus deduplicated totals, including windows with no
eligible alerts. Recipient values and alert content are not copied into the evaluation event.

External sends remain disabled until destination ownership, recipient allowlists, and credentials are
approved for the deployment. The delivery state is not a guarantee that a mailbox user read the
message; `delivered` means the transport accepted it.
