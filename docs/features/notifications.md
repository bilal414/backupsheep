# Notifications

BackupSheep records operational events in the Activity log and can send backup
and restore email. Notification-bot events can also fan out to connected Slack
incoming webhooks and Telegram chats.

## Notification events

Email templates and task paths cover:

- backup completed;
- backup failed or could not start;
- storage validation failed before backup;
- upload to a storage destination failed;
- restore started;
- restore completed;
- restore failed;
- team invitation, email verification, and password reset account messages.

Partial archive completion is recorded in account activity with the number of
successful destinations. It is not sent through the normal all-destinations
backup-success email path.

## Backup email controls

Backup success/failure email uses three layers:

1. The account must allow that event type.
2. The node must allow that event type.
3. The member's active account membership must allow that event type.

The account's primary membership is always included in the relevant recipient
list even if its membership flag is false. Non-primary members can be opted in
or out independently for success and failure. The account owner manages those
membership flags under **Settings → Users** or when creating an invitation.

Restore completion uses the account's success-recipient list. Restore start and
failure use the failure-recipient list. Restore email helpers do not additionally
check the node/account backup toggles.

## Email delivery

The self-hosted site settings support:

- Mailgun;
- Postmark;
- Amazon SES.

The onboarding email step stores the selected provider configuration. Email
content is rendered from HTML and plain-text templates with the configured
application branding. Email-delivery failures are isolated from backup and
restore state transitions so a mail outage does not turn a successful backup
into a failed backup.

Members can register a notification email and send a verification message.
Normal backup recipient selection uses the account membership's user email.

## Slack

Slack is connected through OAuth with an incoming webhook. **Settings →
Notifications** lists the workspace/channel and provides validation and removal
actions. Validation sends a test webhook message.

This Slack notification integration is unrelated to the disabled Slack backup
source card.

## Telegram

An operator adds a channel name and chat ID after adding the configured
BackupSheep bot to the chat/channel. The notification page provides validation
and removal actions. Validation sends a test message through the configured bot
token.

## Channel fan-out boundary

Every connected Slack workspace and Telegram chat for the account is active;
the channel models do not have per-event or enabled switches. Messages written
through the notification-bot pipeline are fanned out to all connected channels,
and one channel failure is caught so it does not block the others.

Group permission codenames exist for `notify_via_email`, `notify_via_slack`, and
`notify_via_telegram`, but the current channel fan-out does not use them for
per-group routing. Do not treat those permissions as channel subscriptions.

## Public-safe failures

Backup failure messages use an allowlisted code, remediation, retryability flag,
and correlation ID. Provider response bodies, credentials, arbitrary exception
text, and command output are excluded from the stable notification contract.
Full diagnostics belong in secured error monitoring and deployment logs.

Some older upload notification fields include node, connection, storage, and
execution endpoint context. Treat notification channels as operationally
sensitive and restrict who can join them.

## Implementation references

- [Account recipient selection and channel fan-out](../../apps/console/account/models.py)
- [Backup notification contract](../../apps/console/node/models.py)
- [Notification models and email providers](../../apps/console/notification/models.py)
- [Notification channel API](../../apps/api/v1/notification/views.py)
- [Notification settings UI](../../apps/console/_templates/console/setting/notification.html)
- [Restore notifications](../../apps/_tasks/integration/restore_common.py)
- [Email templates](../../apps/console/_templates/console/emails)
