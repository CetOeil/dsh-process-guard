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

| Requirement | State in this repository |
|---|---|
| Public, open-source GitHub repository | public at <https://github.com/CetOeil/dsh-process-guard> |
| The GitHub topic `dsh-plugin` | **must be added by hand** — see below |
| README with an install command | `dsh plugin --profile web add dsh-process-guard` |
| An exported `apply(ctx)` module | `lib/index.js` exports `apply`, `name`, and `inject` |

`npm run verify:market` checks everything in that table that a working tree can
answer, and prints the two GitHub-side steps it cannot. Run it before tagging a
release.

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
npm run check                                  # tests, bundle, listing readiness, artifact audit
npm publish --access public --provenance
```

`--provenance` needs a public repository and npm's OIDC flow; run it from CI (the
`publish` workflow does, on a GitHub Release whose tag is exactly
`v<package.json version>`) or from a logged-in machine. The name
`dsh-process-guard` was unclaimed on the public registry when this package was
prepared.

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
