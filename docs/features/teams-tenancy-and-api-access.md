# Teams, tenancy, and API access

BackupSheep supports multiple members per account and multiple accounts per
member. Account scoping and node visibility apply to the console and to API
querysets; group permissions control mapped write and operational actions.

## Memberships and current account

A member can have several account memberships. One is primary for an account
(the owner), and one is marked current for the user's active session/API scope.
The account-switch action only allows a member to switch their own current
membership and only to an account they already belong to.

Account-owned data is not moved when switching. Connections, nodes, storage,
schedules, logs, groups, invitations, and notification channels remain under
their original account.

## Team and Client groups

An account group has a display type:

- **Team** for internal staff;
- **Client** for customer/client access.

The type is descriptive; the group's node selection and permissions establish
actual access.

### Node visibility

The visibility rule is intentionally significant:

- the primary owner sees every node in the current account;
- a non-owner sees the union of nodes selected in all their current-account
  groups;
- if any of those groups has **no nodes selected**, that group is unrestricted
  and grants visibility to every node in the account;
- a non-owner in no groups sees no nodes.

An empty node list therefore means **all nodes**, not no nodes. Select explicit
nodes when creating a restricted Client group.

### Group permissions

Non-owner permissions are the union of the member's group permissions:

| Permission | Mapped capability |
| --- | --- |
| `backup_create` | Start on-demand backup and supported restore/resume actions |
| `backup_download` | Download backup copies |
| `backup_delete` | Delete backup records/copies |
| `schedule_changes` | Create, edit, trigger, pause, resume, or delete schedules |
| `node_changes` | Create, modify, pause/resume, or delete nodes |
| `integration_changes` | Create, modify, or delete source connections |
| `storage_changes` | Create, modify, validate, or delete storage destinations |

Notification permission codenames are also available (`notify_on_success`,
`notify_on_fail`, and per-channel names), but current backup email selection is
driven by account/node toggles and membership flags, and channel fan-out is
account-wide. See [Notifications](notifications.md).

The owner bypasses group permission checks. Safe reads still depend on each
view's current-account and visible-node queryset. A permission never grants
visibility to another account's object.

## Invitations and member management

An invitation contains the invitee's name/email, groups, timezone, and backup
success/failure email flags. Its public link is valid for seven days.

- A new user can create an account from the invite page and is enrolled in the
  invited BackupSheep account.
- An existing user with the matching email signs in and accepts the invite.
- Accepted, cancelled, expired, and unknown links do not enroll a user.
- Resending a pending invite restarts the seven-day window.
- Cancelling a pending invite makes its link unusable immediately.

The owner can update another member's group assignments and membership
notification flags or remove the membership. The user-management endpoint
does not allow the owner to change their own groups through that action. A
group cannot be deleted while it still has members.

## API authentication

The API is mounted at `/api/v1/`. It supports:

- the same CSRF-protected Django session used by the console;
- DRF token authentication using `Authorization: Token <api-key>`.

`POST /api/v1/auth/login/` starts a session and returns the user's API token as
`api_key`. Treat that value as a secret. Most endpoints require authentication;
public login/reset and narrowly scoped callback/webhook endpoints are explicit
exceptions. The browsable API renderer is enabled only when Django `DEBUG` is
on.

## API scoping and action visibility

Core list/query endpoints use the current account. Node, schedule, backup, and
log querysets additionally apply group node visibility. Storage, connections,
groups, invitations, notification channels, and members are filtered to the
current account or its memberships.

Unsafe actions are mapped to group permission codenames in the relevant
viewsets. Because a few older settings/invitation/notification permissions are
membership-based rather than consistently owner- or group-gated, deployments
that need a strict least-privilege management plane should place the API behind
their own access controls and test every delegated role before use.

The backup and restore APIs expose normalized, redacted execution status.
Storage read serializers return credential-presence booleans instead of stored
secrets, while credential fields are replacement-only/write-only.

## Operator checklist for delegated access

1. Create explicit-node Client groups; do not leave the node list empty.
2. Grant only the actions the member needs.
3. Verify console pages and API reads using the delegated account itself.
4. Test that write requests outside the assigned scope return 403 or 404.
5. Keep API tokens out of source control and rotate them when membership or
   operator trust changes.
6. Review the Activity log for membership, schedule, source, storage, backup,
   restore, and authentication events.

## Implementation references

- [Membership and current-account models](../../apps/console/member/models.py)
- [Groups and permission definitions](../../apps/console/account/models.py)
- [Visible-node rules](../../apps/api/v1/utils/api_helpers.py)
- [Group permission gate](../../apps/api/v1/utils/api_permissions.py)
- [Invitation lifecycle](../../apps/console/invite/models.py)
- [Public invitation acceptance](../../apps/console/invite/views.py)
- [Member management and account switching](../../apps/api/v1/member/views.py)
- [API authentication classes](../../apps/api/v1/utils/api_authentication.py)
- [Login/token endpoint](../../apps/api/v1/auth/views.py)
- [REST framework configuration](../../backupsheep/settings.py)
- [API v1 routes](../../apps/api/v1/urls.py)
