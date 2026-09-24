# Publishing

Two independent registries can list this plugin, and they work differently. Only
the first one is `dsh-plugin.org`.

## 1. dsh-plugin.org — automatic, no pull request

The hub at <https://dsh-plugin.org> discovers plugins by scanning public GitHub
repositories that carry the **`dsh-plugin` topic**, then reviews each one by hand.
There is no submission form and no pull request; a listing appears within a
refresh cycle of the topic being added. New entries are labelled `unconfirmed`
until a reviewer checks compatibility.

Its four stated requirements, from <https://dsh-plugin.org/submit>:

| Requirement | State in this repository | Checked by |
|---|---|---|
| Public, open-source GitHub repository | public at <https://github.com/CetOeil/dsh-process-guard> | GitHub-side |
| The GitHub topic `dsh-plugin` | added | GitHub-side |
| README with an install command | `dsh plugin --profile web add dsh-process-guard` | `npm run verify:market` |
| An exported `apply(ctx)` module | `lib/index.js` exports `apply`, `name`, and `inject` | `npm test` |

Each requirement is checked exactly once, by whichever check owns it:
`verify:market` asserts the README install command (the requirement nothing else
covers) and prints the two GitHub-side steps it cannot reach; the `apply(ctx)`
export needs no dedicated check because `test/plugin.test.js` imports it by name,
so losing it fails `npm test` at module load. Run `npm run check` before tagging
a release.

The two manual steps, both on the repository's GitHub page:

1. **Add the topic.** Settings → Topics → add `dsh-plugin`. Without it the
   crawler never sees the repository, which is the single most common reason a
   plugin is not listed.
2. **Set a repository description.** The hub shows it in the listing, and it is
   currently empty. Recommended text (166 characters, inside GitHub's 350 limit):

   ```
   DeepSeek Harness plugin that refuses shell commands killing processes by image name, wildcard, or unfiltered enumeration — the cleanup that closes the DSH GUI window.
   ```

   It front-loads what the plugin does, names the three selector classes the
   matcher actually covers, and ends on the failure it exists to prevent. Avoid
   "prevents" or "blocks all": `SECURITY.md` frames this as a behavioral safety
   net over command text, not a security boundary, and the description should not
   claim more than the matcher delivers.

Once listed, metadata refreshes automatically from the repository, so later
releases need no resubmission. The optional badge template is on the submit page.

## 2. awesome-dsh-plugin — a pull request, and a separate list

[`awesome-dsh-plugin`](https://github.com/awesome-dsh-plugin/awesome-dsh-plugin)
is a curated list with its own rules, unrelated to dsh-plugin.org. It is
optional; skipping it costs nothing on the hub.

Its contribution flow is a pull request adding exactly one file,
`data/plugins/<owner>__<repo>.yml`:

```yaml
url: https://github.com/CetOeil/dsh-process-guard
name: CetOeil/dsh-process-guard
category: security
description:
  en: Blocks DSH shell calls that terminate protected browser, terminal, or harness processes by image name, wildcard, or unfiltered enumeration.
```

Its CI checks, in order: one entry per pull request, a `dsh.bundle` declaration
in the repository's `package.json`, and a repository at least one day old. The
`category` must be one of its fixed set; `security` is valid. The description must
be one line ending with a period and must match what the code does.

## 3. npm — the package itself

`dsh plugin --profile web add dsh-process-guard` resolves the package from npm,
so publishing is a prerequisite for the documented install command to work.
Listing on either registry does not require it, but the README's install line
does.

Releases go out through **trusted publishing (OIDC)**: configure the trusted
publisher on npmjs.com for this repository and `publish.yml`, create a GitHub
Release whose tag is exactly `v<package.json version>`, and the workflow
publishes with an attestation. No npm token is stored.

For a manual publish from a workstation there is no attestation — `--provenance`
is a cloud-CI feature ("when publishing from a supported cloud CI/CD system", per
`npm publish --help`) — and it needs a credential npm is retiring, so prefer the
release path:

```sh
npm run check
npm publish --access public       # no --provenance: a local publish cannot attest
```

The name `dsh-process-guard` was unclaimed on the public registry when this
package was prepared, so `npm view dsh-process-guard` returning **404** is the
expected pre-publish state, not a fault. The same 404 after a publish means
something else — see §4. A publish that reaches the registry and is refused
returns **403**, which is a different problem again: §5.

**0.2.1 was the exception.** Trusted publishing cannot publish a package's
*initial* version — npm requires the package to exist before its settings page
can enable OIDC ([npm/cli#8544](https://github.com/npm/cli/issues/8544), still
open) — so the first release used a granular access token. Every release from
0.2.2 on uses OIDC and needs no token.

## 4. Reading a 404 from the npm registry

The code has several meanings, and only one of them is a problem.

| When | Meaning | Action |
|---|---|---|
| `npm view <name>` before publishing | The name is unclaimed | Publish; this is the green light |
| `npm publish` | npm masks authorization failures as 404 | Treat as "not authorized", not "not found" — check `npm whoami`, token scope, and 2FA |
| `npm view <name>` right after publishing | Read-through cache or propagation | Wait a minute and retry |
| `npm install <name>` / `dsh plugin add <name>` | The package is genuinely absent, or `.npmrc` points at a different registry | `npm config get registry` should be `https://registry.npmjs.org/` |

The `npm publish` row is the one that costs an afternoon. An unauthenticated or
under-scoped token, or a missing one-time password on an account with
"auth-and-writes" 2FA, surfaces as `E404 ... could not be found or you do not
have permission to access it`. Newer npm returns a distinct `EOTP` for the 2FA
case, but the 404 wording still appears. Never read it as "the name is taken".

## 5. E403 on publish: the 2FA requirement

A publish attempt against an unclaimed name logs two `GET 404`s (the packument
lookup) and then a `PUT 403`:

```
http fetch GET 404 https://registry.npmjs.org/dsh-process-guard
notice Publishing to https://registry.npmjs.org/ with tag latest and public access
http fetch PUT 403 https://registry.npmjs.org/dsh-process-guard
error 403 403 Forbidden - PUT https://registry.npmjs.org/dsh-process-guard -
  Two-factor authentication or granular access token with bypass 2fa enabled
  is required to publish packages.
```

Read the two 404s as the name being free — they are not the failure. The `PUT`
is. The token authenticated (a bad token gives 401), so this is not a credential
problem.

npm's own follow-up hint — "you or one of your dependencies are requesting a
package version that is forbidden by your security policy" — is generic `E403`
boilerplate and is unrelated. Ignore it.

### Enable 2FA first, or neither remedy is available

Check the account before touching tokens:

```sh
npm profile get        # look at the "two-factor auth" line
```

If it says **disabled**, that is the whole problem, and it is circular: npm
requires 2FA (or a token allowed to bypass it) to publish, but npm only offers
the granular token's **"Bypass 2FA"** switch when the account already has 2FA
enabled. Generating a new granular token without that prerequisite produces a
token that authenticates fine and still fails the `PUT` with this exact 403 —
which reads like a token problem and is not one.

So the order is fixed:

1. Enable 2FA at <https://www.npmjs.com/settings/~/profile> (authenticator app;
   save the recovery codes). This cannot be skipped — npm does not exempt a
   first-time publisher.
2. Then either publish interactively with `npm publish --access public
   --otp=<code>`, or create the bypass token for unattended use.

### The two remedies, once 2FA is on

- **Interactive, one-off:** `npm publish --access public --otp=<code>`, with the
  code from the authenticator. npm's `otplease` wrapper is what retries with it.
- **Token, for the bootstrap publish only:** a **Granular Access Token** at
  <https://www.npmjs.com/settings/~/tokens>. The settings matter, and two of the
  three traps below produce a 403 that looks like a 2FA problem but is not.

### Choosing token settings — three traps

The registry reports these very differently, so read the message before changing
anything:

| Error on `PUT` | Real cause |
|---|---|
| `Two-factor authentication or granular access token with bypass 2fa enabled is required` | The token cannot satisfy 2FA. Tick **Bypass 2FA**. |
| `You may not perform that action with these credentials` | The token authenticated but lacks permission. Not a 2FA problem at all. |
| `409 Conflict — Failed to save packument` | Transient. Nothing is misconfigured; wait a minute and retry. |

The middle row has two causes, both silent:

- **Permissions: "Read and write (stage only)"** — added 2026-09-18, and npm
  rejects direct `npm publish` with it *even when bypass 2FA is enabled*. Use
  plain **Read and write**.
- **Packages: a select list.** While a package name has no published versions it
  may not be selectable, so a scoped token silently cannot cover it. Use **All
  packages**.

So the working bootstrap token is: **Read and write** (not stage-only), **All
packages**, **Bypass 2FA enabled**, expiry 30–90 days.

### This whole path is being retired

Bypass-2FA tokens **lose direct publishing in January 2027**
([changelog](https://github.blog/changelog/2026-07-31-restricting-npm-bypass-2fa-granular-access-tokens/)).
The replacement is trusted publishing (OIDC), which is what `publish.yml` now
uses. Two things about it are worth knowing:

- **`actions/setup-node` must not set `registry-url`.** It writes an `.npmrc`
  containing a `NODE_AUTH_TOKEN` placeholder, and that placeholder overrides
  npm's native OIDC exchange, so the job fails on auth with nothing wrong with
  the trusted publisher. Keep `id-token: write` and `--provenance`; drop
  `registry-url`.
- **OIDC cannot publish a package's first version.** npm requires the package to
  exist before its settings page can enable trusted publishing
  ([npm/cli#8544](https://github.com/npm/cli/issues/8544), still open). Hence the
  one-off token above: publish once, then configure the trusted publisher, then
  drop the token entirely.

## Release checklist

1. `npm run check` passes — tests, bundle contract, listing readiness, and the
   exact packed file set.
2. `package.json` `version` and the `CHANGELOG.md` entry agree.
3. Commit, then push `main` and the tag `v<version>`.
4. Add the `dsh-plugin` topic and a repository description, if this is the first
   release.
5. Publish by creating the GitHub Release for that tag — it triggers
   `.github/workflows/publish.yml`, which publishes over OIDC with an
   attestation and needs no secret.
6. Verify, don't assume:
   ```sh
   npm view <name> version                       # the version is live
   npm audit signatures                          # "verified registry signature"
                                                 # and "verified attestation"
   git checkout v<version> && npm pack --dry-run --json   # shasum must match
   ```
   A direct `Invoke-WebRequest`/`curl` of the tarball URL is not a good check —
   it can 404 from environments that npm's own client handles fine.
7. Confirm the hub listing at
   <https://dsh-plugin.org/plugins/CetOeil/dsh-process-guard> after the next scan.

If a release fails at the publish step, read the exact `PUT` error against §5
before changing anything: a `409` is transient, a `403` naming 2FA is a token
setting, and a `403` saying "these credentials" is a different token setting.
