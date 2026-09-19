/**
 * Pure, dependency-free command matcher for dsh-process-guard.
 *
 * The matcher answers exactly one question about a shell command string: does it
 * terminate processes selected by IMAGE NAME (or every process handed back by a
 * process enumeration), rather than by an explicit PID or a process handle the
 * caller owns?
 *
 * Why that question: the DSH Web GUI is a browser client on the loopback port,
 * and the harness server is a `node` process. An image-name kill therefore
 * destroys the harness's own host processes — the GUI window disappears and the
 * running turn is recorded as interrupted. Explicit-PID and handle-based kills
 * cannot make that mistake.
 *
 * It is deliberately a static, conservative heuristic over the command text:
 * no process enumeration, no host lookups, no filesystem access. It runs inside
 * a synchronous guard on the tool-call path. See docs/DESIGN.md for the threat
 * model and the list of known bypasses this heuristic does NOT stop.
 *
 * @module dsh-process-guard/matcher
 */

/**
 * Image names whose termination can take down the GUI session or the harness
 * itself. Browsers first (the GUI is one of them), then the harness host tree.
 */
export const DEFAULT_PROTECTED_IMAGES = Object.freeze([
  // Browsers — the DSH Web GUI runs in one of these.
  'chrome',
  'msedge',
  'msedgewebview2',
  'firefox',
  'brave',
  'vivaldi',
  'opera',
  'iexplore',
  // The harness's own host processes.
  'node',
  'dsh',
  'pwsh',
  'powershell',
  'conhost',
  'windowsterminal',
  'wt'
]);

/** Shell tools whose command strings are inspected by default. */
export const DEFAULT_TOOLS = Object.freeze(['pwsh', 'bash', 'terminal']);

/** Termination primitives, matched against the string-and-comment-blanked view. */
const KILL_VERBS = Object.freeze([
  { rule: 'stop-process', re: /\bStop-Process\b/i },
  { rule: 'taskkill', re: /\btaskkill(?:\.exe)?\b/i },
  { rule: 'wmic-delete', re: /\bwmic(?:\.exe)?\b[^\n]*\bdelete\b/i },
  { rule: 'kill-method', re: /\.\s*(?:Kill|CloseMainWindow)\s*\(/i },
  { rule: 'terminate-process', re: /\bTerminateProcess\b/i },
  { rule: 'pskill', re: /\bpskill(?:\.exe)?\b/i },
  { rule: 'killall', re: /\bkillall\b/i },
  { rule: 'pkill', re: /\bpkill\b/i },
  { rule: 'kill', re: /\bkill\b/i }
]);

/** Cmdlets that hand back arbitrary processes rather than a selected one. */
const ENUMERATION = /\bGet-Process\b|\bGet-CimInstance\b|\bGet-WmiObject\b|\btasklist\b/i;

/** Selectors that mean "every process", regardless of any enumeration. */
const WILDCARD_SELECTOR = /-Name\s*\*|\/IM\s*\*|\bkillall\s+-r\b|\bpkill\s+-r\b/i;

/** Selectors that name an explicit PID, which cannot hit the wrong process. */
const ID_SELECTOR = /(?:^|\s)-Id\b|\/PID\b|--pid\b|\bkill\s+(?:-\S+\s+)*\d/i;

/** A narrowing filter, i.e. the command selects a subset before killing. */
const NARROWING_FILTER = /\bWhere-Object\b|\bWhere\b|\s-Filter\b|\bpgrep\b|\bSelect-String\b/i;

/**
 * Markers of the documented safe pattern: narrow to a headless instance or to a
 * dedicated `--user-data-dir`, so the user's own browser can never match.
 */
const SAFE_FILTER = /--headless\b|--user-data-dir\b|\bheadless\b/i;

/**
 * Primitives that execute a *string* as code. Paired with a termination verb that
 * is visible only inside a quoted literal, they identify the standard way to hide
 * a kill from a command-text matcher: `Invoke-Expression "Stop-Process -Name
 * chrome"`, `cmd /c "taskkill /IM msedge.exe /F"`, `bash -c "killall chrome"`.
 */
const INDIRECTION = /\bInvoke-Expression\b|\biex\b|\beval\b|cmd(?:\.exe)?\s*\/c\b|\b(?:bash|sh|pwsh|powershell)(?:\.exe)?\s+-(?:[cC]|Command)\b/i;

/** Segment separators. `|` is deliberately NOT one: a pipeline is one unit. */
const SEGMENT_BREAK = /\r?\n|;|&&|\|\|/g;

/** Normalize an image name for comparison (case, optional `.exe`, surrounding space). */
export function normalizeImage(image) {
  return String(image).trim().toLowerCase().replace(/\.exe$/, '');
}

/** Escape a string for literal use inside a RegExp. */
function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Build the two length-preserving views the matcher needs:
 *
 * - `noStrings` blanks quoted literal contents (and comments): the view used to
 *   find termination VERBS, so `Write-Output "Stop-Process -Name chrome"` is not
 *   mistaken for a kill.
 * - `noComments` keeps quoted literals but blanks comments: the view used to find
 *   TARGETS and filters, so a quoted target (`-Name "chrome"`) and a quoted
 *   filter pattern (`'*--headless*'`) are both visible while `-Id 5 # chrome` is
 *   not.
 *
 * Both views keep every character position and every newline, so a single set of
 * segment boundaries applies to both.
 *
 * @param command - the raw command string.
 * @returns the two masked views.
 */
export function maskViews(command) {
  const text = String(command);
  const noStrings = text.split('');
  const noComments = text.split('');
  let quote = null;
  let escaped = false;
  let inComment = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (inComment) {
      if (ch === '\n') inComment = false;
      else noComments[i] = ' ';
      noStrings[i] = ch === '\n' ? '\n' : ' ';
      continue;
    }
    if (quote !== null) {
      noStrings[i] = ch === '\n' ? '\n' : ' ';
      if (escaped) {
        escaped = false;
        continue;
      }
      if (quote === '"' && (ch === '`' || ch === '\\')) {
        escaped = true;
        continue;
      }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '#') {
      noStrings[i] = ' ';
      noComments[i] = ' ';
      inComment = true;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      noStrings[i] = ' ';
      continue;
    }
  }
  return { noStrings: noStrings.join(''), noComments: noComments.join('') };
}

/**
 * Split a command into statements (newline, `;`, `&&`, `||`) while keeping both
 * masked views and the raw text aligned. Pipelines stay whole so that
 * `Get-Process chrome | Stop-Process` is analyzed as one unit.
 *
 * @param command - the raw command string.
 * @returns one entry per non-empty statement.
 */
export function splitSegments(command) {
  const text = String(command);
  const { noStrings, noComments } = maskViews(text);
  const segments = [];
  let start = 0;
  SEGMENT_BREAK.lastIndex = 0;
  for (const match of noStrings.matchAll(SEGMENT_BREAK)) {
    segments.push({ raw: text.slice(start, match.index), noStrings: noStrings.slice(start, match.index), noComments: noComments.slice(start, match.index) });
    start = match.index + match[0].length;
  }
  segments.push({ raw: text.slice(start), noStrings: noStrings.slice(start), noComments: noComments.slice(start) });
  return segments.filter((segment) => segment.noStrings.trim().length > 0);
}

/** First matching termination verb in the string-blanked view, or undefined. */
function findKillVerb(noStrings) {
  for (const verb of KILL_VERBS) if (verb.re.test(noStrings)) return verb.rule;
  return undefined;
}

/** Protected image names mentioned anywhere in the comment-blanked segment. */
function findProtectedImages(noComments, protectedImages) {
  const found = [];
  for (const image of protectedImages) {
    const re = new RegExp(`(?<![\\w.-])${escapeRegex(image)}(?:\\.exe)?(?![\\w.-])`, 'i');
    if (re.test(noComments)) found.push(image);
  }
  return found;
}

/** Shorten an excerpt for the model-facing reason line. */
function excerptOf(raw) {
  const flat = raw.replace(/\s+/g, ' ').trim();
  return flat.length > 120 ? `${flat.slice(0, 117)}...` : flat;
}

/**
 * Classify one statement.
 *
 * Precedence, highest first:
 *  1. a protected image named as a target is a `flag` (rule `protected-image-kill`),
 *     unless the statement also narrows with a headless / `--user-data-dir`
 *     filter AND `safeFilterAllows` is on — the documented safe pattern;
 *  2. a kill verb applied to an enumeration or a wildcard selector with no target
 *     named is a `flag` (rules `blanket-enumeration` / `blanket-wildcard`);
 *  3. everything else is an `allow`: an explicit PID, a `-PassThru` handle, an
 *     unprotected image, or simply no kill verb.
 *
 * @param segment - one statement from {@link splitSegments}.
 * @param protectedImages - normalized image names.
 * @param options - `safeFilterAllows` toggle.
 * @returns a finding, or undefined when the statement contains no kill verb.
 */
function analyzeSegment(segment, protectedImages, options) {
  const verb = findKillVerb(segment.noStrings);
  const images = findProtectedImages(segment.noComments, protectedImages);
  const excerpt = excerptOf(segment.raw);
  if (verb === undefined) {
    // A verb that is visible ONLY inside a quoted literal is normally just text
    // (`Write-Output "…"`). Combined with an indirection primitive that executes
    // the literal, it is a hidden kill instead.
    const hiddenVerb = findKillVerb(segment.noComments);
    if (hiddenVerb !== undefined && images.length > 0 && INDIRECTION.test(segment.noComments)) {
      return { kind: 'flag', rule: 'indirect-execution', verb: hiddenVerb, images, excerpt };
    }
    return undefined;
  }
  if (images.length > 0) {
    const scoped = NARROWING_FILTER.test(segment.noComments);
    const safe = options.safeFilterAllows && scoped && SAFE_FILTER.test(segment.noComments);
    if (safe) return { kind: 'allow', rule: 'safe-scoped-filter', verb, images, excerpt };
    return { kind: 'flag', rule: 'protected-image-kill', verb, images, excerpt };
  }
  const hasIdSelector = ID_SELECTOR.test(segment.noComments);
  if (!hasIdSelector && WILDCARD_SELECTOR.test(segment.noComments)) {
    return { kind: 'flag', rule: 'blanket-wildcard', verb, images, excerpt };
  }
  if (!hasIdSelector && ENUMERATION.test(segment.noStrings)) {
    return { kind: 'flag', rule: 'blanket-enumeration', verb, images, excerpt };
  }
  return { kind: 'allow', rule: hasIdSelector ? 'explicit-pid' : 'handle-or-unprotected', verb, images, excerpt };
}

/** Model-facing explanation for one flagged statement. */
function buildReason(finding) {
  if (finding.rule === 'indirect-execution') {
    const images = finding.images.map((image) => `"${image}"`).join(', ');
    return `process-guard: blocked — this executes a command string that itself terminates ${images} by image name. Indirect execution is how an image-name kill hides from inspection, and ${images} may be the browser hosting the DSH Web GUI or the harness's own process. Run the safe form directly: Start-Process ... -PassThru, then $p.Kill(); or target explicit PIDs with -Id.`;
  }
  if (finding.rule === 'protected-image-kill') {
    const images = finding.images.map((image) => `"${image}"`).join(', ');
    return `process-guard: blocked — this terminates ${images} by image name. That image may be the browser hosting the DSH Web GUI (http://127.0.0.1:3080) or the harness's own process, and killing it closes the GUI window and drops this session's client connection. Kill only processes you started: $p = Start-Process ... -PassThru; if (-not $p.WaitForExit(25000)) { $p.Kill() } — or target explicit PIDs with -Id.`;
  }
  return `process-guard: blocked — this terminates every process returned by a process enumeration, with no name or PID selector, so it can kill the browser hosting the DSH Web GUI and the harness's own node process. Target explicit PIDs with -Id, or filter to the instance you started (--headless / --user-data-dir).`;
}

/**
 * Evaluate one command string.
 *
 * @param command - the shell command about to run.
 * @param options - `protectedImages`, `mode` (`'deny'` default, or `'ask'`), `safeFilterAllows`.
 * @returns `{ kind: 'allow' | 'deny' | 'ask', rule, images, excerpt, reason?, findings }`.
 *   `mode` only relabels a flagged result; it never turns a flag into an allow.
 */
export function evaluateCommand(command, options = {}) {
  const protectedImages = (options.protectedImages ?? DEFAULT_PROTECTED_IMAGES).map(normalizeImage);
  const mode = options.mode === 'ask' ? 'ask' : 'deny';
  const safeFilterAllows = options.safeFilterAllows !== false;
  const findings = [];
  for (const segment of splitSegments(command)) {
    const finding = analyzeSegment(segment, protectedImages, { safeFilterAllows });
    if (finding !== undefined) findings.push(finding);
  }
  const flagged = findings.filter((finding) => finding.kind === 'flag');
  if (flagged.length === 0) {
    return {
      kind: 'allow',
      rule: findings.find((finding) => finding.kind === 'allow')?.rule ?? 'no-match',
      images: [],
      excerpt: '',
      findings
    };
  }
  const top = flagged[0];
  return {
    kind: mode,
    rule: top.rule,
    images: top.images,
    excerpt: top.excerpt,
    reason: buildReason(top),
    findings
  };
}
