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

```sh
npm run check                     # tests, bundle, listing readiness, artifact audit
npm publish --access public       # add --provenance only from CI
```

`--provenance` is a cloud-CI feature — `npm publish --help` describes it as
"when publishing from a supported cloud CI/CD system" — so the `publish` workflow
is what produces an attestation, on a GitHub Release whose tag is exactly
`v<package.json version>`. A local publish cannot attest, and adding the flag
there only invites a confusing failure.

The name `dsh-process-guard` was unclaimed on the public registry when this
package was prepared, so `npm view dsh-process-guard` returning **404** is the
expected pre-publish state, not a fault. The same 404 after a publish means
something else — see §4. A publish that reaches the registry and is refused
returns **403**, which is a different problem again: §5.

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
- **Durable, and required for CI:** create a **Granular Access Token** at
  <https://www.npmjs.com/settings/~/tokens> with read-and-write permission and
  **"Bypass 2FA" enabled**, then set it as `//registry.npmjs.org/:_authToken` in
  `~/.npmrc` locally and as the `NPM_TOKEN` secret for the `publish` workflow.

A token without the bypass permission fails the workflow with this same 403, so
`NPM_TOKEN` must be the granular bypass-2FA token, not a classic one.

## Release checklist

1. `npm run check` passes — tests, bundle contract, listing readiness, and the
   exact packed file set.
2. `package.json` `version` and the `CHANGELOG.md` entry agree.
3. Commit, then push `main`.
4. Add the `dsh-plugin` topic and a repository description, if this is the first
   release.
5. Publish to npm, either by creating the GitHub Release `v<version>` (which
   triggers `.github/workflows/publish.yml`) or with the manual command above.
6. Confirm the hub listing at
   <https://dsh-plugin.org/plugins/CetOeil/dsh-process-guard> after the next scan.
