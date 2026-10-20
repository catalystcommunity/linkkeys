# App access policies and password locks

An admin can control which applications each account can sign in to. An admin
can also lock the password of an account. Both settings are for cases such as
a shared demo account, or accounts that must not use some applications.

## App access policies

Manage policies on `/app/admin/access`. Each operation needs the `admin`
relation. The `Admin` service has the same operations for an API caller:
`list-app-access-policies`, `set-app-access-policy`,
`remove-app-access-policy`, and `preview-app-access`.

### Parts of a policy

- **Name.** Each policy has a different name.
- **Type.** `deny` blocks the domains that match. `allow` permits only the
  domains that match.
- **Domain patterns.** One or more application domains. In a pattern, `*`
  matches any characters, dots included. The server stores patterns in
  lowercase, without a trailing dot.

  | Pattern | Matches | Does not match |
  |---|---|---|
  | `*.ru` | `shop.ru`, `a.b.ru` | `ru`, `guru`, `shop.ru.example.com` |
  | `example.com` | `example.com` | `www.example.com` |
  | `app-*.example.com` | `app-1.example.com` | `web-1.example.com` |
  | `*` | every domain | a local app (no domain) |

- **Message (optional).** Plain text, up to 1000 bytes. A blocked user sees it
  below the standard message.
- **Targets.** The accounts the policy applies to. A policy without targets
  applies to no account.

  | Target | Applies to |
  |---|---|
  | Every account | All accounts. |
  | One account | One account, by user ID. |
  | A group | Accounts with the `member` relation on object type `group` and this group name. |
  | Accounts with a detail | Accounts whose active claims meet a condition. |

  Claim conditions:

  | Condition | True when |
  |---|---|
  | `present` | The account has an active claim of this type. |
  | `absent` | The account has no active claim of this type. |
  | `equals` | A value equals the condition value. Letter case is ignored. |
  | `age_under` N | A `YYYY-MM-DD` value is a birth date less than N years ago. |
  | `age_at_least` N | A `YYYY-MM-DD` value is a birth date N or more years ago. |

  A value that does not parse does not match. Use a claim type that the account
  holder cannot change (for example `admin_only` or a verified claim). If the
  holder can change or remove the claim, the holder can remove the policy from
  the account. To cover accounts without the claim, add an `absent` target.

### Decision rules

For each sign-in, the server finds the policies that apply to the account:

1. If a `deny` policy has a matching pattern, the sign-in stops. Deny wins.
2. Else, if one or more `allow` policies apply, the domain must match a pattern
   in one of them. Otherwise the sign-in stops.
3. Else, the sign-in continues.

A local app has no domain, so no pattern matches it. A `deny` policy never
blocks a local app. An `allow` policy always blocks it.

When policies block a sign-in, the user sees the messages of the policies that
blocked it. For rule 1, these are the matching `deny` policies. For rule 2,
these are all `allow` policies that apply.

### Where the server applies the rules

| Sign-in path | Result when blocked |
|---|---|
| `BrowserAuthorization/inspect` | `access_denied` is set. The UI shows a blocked page. |
| `BrowserAuthorization/complete` and every assertion issued by finalize | Refused with `forbidden` before the request nonce is used. |
| `POST /rp/authorize/validate` with `user_id` | `access_denied` is set. `already_consented` is absent. |
| `POST /rp/authorize/finalize` | HTTP 403, `ApiError` code `forbidden`, the messages in `message`. |
| `inspect-local-rp` | `admission` is `blocked`, `access_denied` is set. The app is not recorded. |
| `complete-local-rp` | Refused with `forbidden`. |
| `inspect-act-as` | `access_denied` is set when the grantee or the audience is blocked. |
| `complete-act-as` and `ActAs/refresh-grant` | Refused. A new policy also stops the renewal of existing grants. |

A blocked sign-in stores no claim values and no consent grant. If the policy
is removed, the same sign-in request can complete.

If the server cannot read the policies, the sign-in stops.

### Test an account

The **Test an account** panel calls `preview-app-access`. It shows the policies
that apply to the account, the policies that block the domain, and the
messages. Leave the domain empty to test a local app.

## Password lock

Lock the password on the account page (`/app/admin/users/<id>`) or with
`Admin/set-user-password-lock`. The operation needs the `admin` relation.

A locked account cannot:

- change its own password (`Account/change-password` answers 403);
- receive a password recovery email (the public answer does not change);
- use a recovery link that was sent before the lock.

An admin can still set a new password with `reset-password`. `AdminUser` has
`password_locked: true` only while the lock is set. The account page then shows
a note in place of the change-password form.

## Example: a shared demo account

1. Create the account and set its password.
2. On the account page, select **Lock the password**.
3. On `/app/admin/access`, add an `allow` policy with the demo application
   domains and a target **One account** for the demo account. Add a message,
   for example "This is a shared demo account."
4. In **Test an account**, check one permitted domain and one other domain.
