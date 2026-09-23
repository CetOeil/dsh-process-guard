/**
 * Dependency-free command matcher for dsh-process-guard.
 *
 * This is a behavioral guard over shell text, not a shell parser or a security
 * boundary. It recognizes the process-termination forms an agent is likely to
 * emit and deliberately fails closed for wildcard and unfiltered selections.
 * See docs/DESIGN.md for the threat model and known limits.
 *
 * @module dsh-process-guard/matcher
 */

/** Browsers, harness hosts, and terminal hosts that must not be killed by name. */
export const DEFAULT_PROTECTED_IMAGES = Object.freeze([
  // Chromium-family browsers on Windows, Linux, and macOS.
  'chrome',
  'google-chrome',
  'google-chrome-stable',
  'chromium',
  'chromium-browser',
  'msedge',
  'microsoft-edge',
  'microsoft-edge-stable',
  'msedgewebview2',
  'brave',
  'brave-browser',
  'vivaldi',
  'opera',
  // Other common GUI browsers.
  'firefox',
  'safari',
  'iexplore',
  // Harness and shell host processes.
  'node',
  'dsh',
  'pwsh',
  'powershell',
  'bash',
  'zsh',
  'conhost',
  'windowsterminal',
  'terminal',
  'iterm2',
  'wt'
]);

/** Shell-style tools whose `command` argument is inspected by default. */
export const DEFAULT_TOOLS = Object.freeze([
  'pwsh',
  'bash',
  'terminal',
  'shell',
  'powershell',
  'cmd',
  'exec',
  'run_command'
]);

/**
 * Shells whose `-c` / `-Command` argument is a command string. A kill written
 * inside one is an invocation, so the payload is searched even though the
 * quoting hides it from the verb view.
 */
const SHELL_EXECUTABLES = Object.freeze(['bash', 'sh', 'zsh', 'dash', 'ksh', 'ash', 'fish', 'pwsh', 'powershell']);

/**
 * Commands whose `-c` argument is a command string but which are not
 * themselves shells: `su -c`, `runuser -c`, `script -c` all run the text.
 */
const INLINE_CODE_EXECUTABLES = Object.freeze([...SHELL_EXECUTABLES, 'su', 'runuser', 'script']);

/**
 * Interpreters whose inline-code flag runs a program that can shell out. Same
 * reasoning as the shells: `python -c "os.system('killall chrome')"` terminates
 * the process just as directly as `killall chrome`.
 */
const INTERPRETER_EXECUTABLES = Object.freeze(['python', 'python3', 'perl', 'ruby', 'node', 'nodejs', 'php', 'osascript', 'deno', 'bun']);

/**
 * Commands that run whatever command follows them, so the token after the
 * wrapper is in command position (`sudo killall chrome`, `time pkill chrome`).
 *
 * The list is enumerated, not inferred: a program that executes its arguments
 * is only covered once it is named here. `ssh` is deliberately absent — it runs
 * on another machine, where it cannot close this one's GUI.
 */
const EXEC_WRAPPERS = new Set([
  'sudo', 'doas', 'su', 'runuser', 'command', 'builtin', 'exec', 'env', 'nohup', 'time', 'nice', 'ionice',
  'setsid', 'stdbuf', 'timeout', 'watch', 'xargs', 'parallel', 'busybox', 'toybox',
  'systemd-run', 'strace', 'ltrace', 'wsl', 'chroot', 'flock', 'script', 'nsenter', 'unshare'
]);

/** Shell keywords that close a preceding clause, leaving the next token in command position. */
const COMMAND_KEYWORDS = new Set(['do', 'then', 'else', 'elif', 'elseif', 'fi', 'done', 'esac', '!']);

/** A `NAME=value` environment-assignment prefix (`FOO=1 killall chrome`). */
const ENV_ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=\S*$/;

/** A wrapper's own option or duration argument (`-o0`, `-c3`, `5`, `10s`, `1.5`). */
const WRAPPER_OPTION = /^(?:-\S+|\d+(?:\.\d+)?[smhd]?)$/;

/** A filesystem path prefix (`./pkill`, `C:\tools\pskill.exe`, `/usr/bin/pkill`). */
const PATH_PREFIX = /^(?:\.{0,2}[\\/]|[A-Za-z]:[\\/]|[\w.-]+[\\/])+$/;

/** A path-shaped wrapper argument (`/usr/bin/`, `/tmp/lock`, `.\x`, `C:\dir`). */
const PATH_TOKEN = /^(?:\.{1,2}[\\/]|[A-Za-z]:[\\/]|\/)/;

/** PowerShell scope qualifiers that prefix a variable name (`$global:p`). */
const VARIABLE_SCOPE = /^(?:global|script|local|private|env|using):/i;

const COMMAND_KILL_VERBS = Object.freeze([
  { rule: 'stop-process', re: /\b(?:Stop-Process|spps)\b/i },
  { rule: 'taskkill', re: /\btaskkill(?:\.exe)?\b/i },
  { rule: 'wmic-terminate', re: /\bwmic(?:\.exe)?\b[^\r\n]*(?:\bdelete\b|\bcall\s+terminate\b)/i },
  { rule: 'cim-terminate', re: /\b(?:Invoke-CimMethod|Invoke-WmiMethod|Remove-CimInstance)\b/i, confirm: /\b(?:Terminate|Win32_Process)\b/i },
  { rule: 'pskill', re: /\bpskill(?:\.exe)?\b/i },
  { rule: 'tskill', re: /\btskill(?:\.exe)?\b/i },
  { rule: 'killall', re: /\bkillall\b/i },
  { rule: 'pkill', re: /\bpkill\b/i },
  { rule: 'kill', re: /\bkill\b/i }
]);

const METHOD_KILL_VERBS = Object.freeze([
  { rule: 'kill-method', re: /\.\s*(?:Kill|CloseMainWindow|Terminate)\s*\(/i },
  { rule: 'terminate-process', re: /(?:::|\.)\s*TerminateProcess\s*\(/i }
]);

const ENUMERATION_COMMAND = /\b(?:Get-Process|gps|ps|Get-CimInstance|gcim|Get-WmiObject|gwmi|tasklist)\b/ig;
const ENUMERATION_ANYWHERE = /\b(?:Get-Process|gps|ps|Get-CimInstance|gcim|Get-WmiObject|gwmi|tasklist)\b/i;
const ID_SELECTOR = /(?:^|\s)-(?:Id|ProcessId)\b|\/PID\b/i;
/**
 * A quoted or bare token carrying a wildcard/glob character.
 *
 * Every quantifier is bounded. An unbounded `\S*` here sits inside an unbounded
 * `[^|;\r\n]*` scan, so a statement containing a process command plus a long run
 * without `|`, `;`, CR, or LF made the engine rescan the remainder from every
 * backtrack position — quadratic, and 21 s of synchronous time on a 200 KB
 * command, which the guard would spend blocking the tool call. The bounds are
 * far wider than any real selector.
 */
const WILDCARD_TOKEN = String.raw`(?:"[^"]{0,200}[*?\[][^"]{0,200}"|'[^']{0,200}[*?\[][^']{0,200}'|\S{0,200}[*?\[]\S{0,200})`;
/**
 * The clause bodies of `Where-Object` and its `?` alias, each cut at the next
 * pipeline or statement boundary. `FILTER_CLAUSE_ANY` is the non-global twin,
 * because `RegExp.prototype.test` on a global regex advances `lastIndex`.
 */
const FILTER_CLAUSE = /\bWhere-Object\b|(?:^|[|\s])\?(?=\s|\{)/gi;
const FILTER_CLAUSE_ANY = /\bWhere-Object\b|(?:^|[|\s])\?(?=\s|\{)/i;
/**
 * A comparison that can exclude processes. `-ne`/`-notlike`/`-notmatch` and a
 * bare property read are excluded on purpose: `Where-Object { $_.Name -ne 'zzz' }`
 * and `Where-Object { $_.ProcessName }` keep every process in the pipeline.
 */
const NARROWING_COMPARISON = /(?:\$_\s*\.\s*)?\b(?:Name|ProcessName|CommandLine|Path|ExecutablePath|MainModule|Description)\b\s*-(?:eq|like|match|contains|in)\b\s*(?:"([^"]{0,200})"|'([^']{0,200})'|(\S{0,200}))/i;
/** An operand that cannot exclude anything: a bare glob, or an empty string. */
const NON_SELECTING_OPERAND = /^(?:[*?%]|\.\*|\.\+|)$/;
/** A CIM/WMI `-Filter`/`-Query` predicate that names a process and compares it. */
const CIM_PREDICATE = /-(?:Filter|Query)\s+["']?[^"']{0,200}\b(?:Name|ProcessId|Handle|ExecutablePath|CommandLine)\b\s*(?:=|like|LIKE)\s*["']?([^"'\s]{0,200})/i;
/** Process-variable parameters whose value is a variable name, not a target. */
const VARIABLE_PARAMETER = /-(?:Error|Warning|Information|Out|Pipeline)Variable\s+(?:"[^"]{0,200}"|'[^']{0,200}'|\S{0,200})/gi;
const POSITIVE_SAFE_FILTER = /(?:\$_\s*\.\s*)?CommandLine\s+-(?:like|match)\s*["'][^"']{0,200}(?:--headless|--user-data-dir)[^"']{0,200}["']|(?:\$_\s*\.\s*)?CommandLine\s*\.\s*Contains\s*\(\s*["'][^"']{0,200}(?:--headless|--user-data-dir)/i;
const UNSAFE_FILTER_LOGIC = /-(?:notlike|notmatch|or)\b|\|\||\$true\b/i;
const NAMED_WILDCARD_SELECTOR = new RegExp(
  [
    // `-Name`/`-ProcessName` selects images only under a process command; the
    // same parameter on `find`, `Get-ChildItem`, or `Select-String` is unrelated.
    String.raw`\b(?:Stop-Process|spps|taskkill|kill|killall|pkill|pskill|tskill|Get-Process|gps|ps)\b[^|;\r\n]{0,200}(?:-(?:Name|ProcessName))\s*(?:[:=]\s*)?${WILDCARD_TOKEN}`,
    // `/IM` is taskkill's image selector and appears in no other tool.
    String.raw`\/IM\s*(?:[:=]\s*)?${WILDCARD_TOKEN}`,
    // A positional wildcard handed to a process cmdlet: `Get-Process '*' | …`.
    String.raw`\b(?:Stop-Process|spps|Get-Process|gps|ps)\b[^|;\r\n]{0,200}${WILDCARD_TOKEN}`
  ].join('|'),
  'i'
);
const PROCESS_LOOKUP = /\b(?:Get-Process|gps|ps|Get-CimInstance|gcim|Get-WmiObject|gwmi|GetProcessesByName)\b/i;
const MAX_INDIRECTION_DEPTH = 4;

/** Normalize an image name for comparison. */
export function normalizeImage(image) {
  return String(image).trim().toLowerCase().replace(/\.(?:exe|com|app)$/i, '');
}

/** Escape a string for literal use inside a RegExp. */
function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Whether `#` starts a shell/PowerShell comment at this position. */
function startsLineComment(text, index) {
  if (index === 0) return true;
  const before = text[index - 1];
  return /\s|[;|&({]/.test(before) && before !== '`' && before !== '\\';
}

/**
 * Build length-preserving views of a command.
 *
 * `noStrings` hides quoted literals and comments for invocation detection.
 * `noComments` keeps strings, because selectors are commonly quoted. Newlines
 * inside strings are blanked in `noStrings` so they cannot split a statement.
 */
export function maskViews(command) {
  const text = String(command);
  const noStrings = text.split('');
  const noComments = text.split('');
  let quote = null;
  let escaped = false;
  let inLineComment = false;
  let inBlockComment = false;

  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    const next = text[i + 1];

    if (inBlockComment) {
      noStrings[i] = ch === '\n' ? '\n' : ' ';
      noComments[i] = ch === '\n' ? '\n' : ' ';
      if (ch === '#' && next === '>') {
        noStrings[i + 1] = ' ';
        noComments[i + 1] = ' ';
        i += 1;
        inBlockComment = false;
      }
      continue;
    }
    if (inLineComment) {
      if (ch === '\n') {
        inLineComment = false;
        noStrings[i] = '\n';
      } else {
        noStrings[i] = ' ';
        noComments[i] = ' ';
      }
      continue;
    }
    if (quote !== null) {
      noStrings[i] = ' ';
      if (escaped) {
        escaped = false;
        continue;
      }
      if (quote === '"' && (ch === '`' || ch === '\\')) {
        escaped = true;
        continue;
      }
      if (quote === "'" && ch === "'" && next === "'") {
        noStrings[i + 1] = ' ';
        i += 1;
        continue;
      }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '<' && next === '#') {
      noStrings[i] = ' ';
      noComments[i] = ' ';
      noStrings[i + 1] = ' ';
      noComments[i + 1] = ' ';
      i += 1;
      inBlockComment = true;
      continue;
    }
    if (ch === '#' && startsLineComment(text, i)) {
      noStrings[i] = ' ';
      noComments[i] = ' ';
      inLineComment = true;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      noStrings[i] = ' ';
    }
  }
  return { noStrings: noStrings.join(''), noComments: noComments.join('') };
}

/** Index of the previous/next non-whitespace character. */
function significantIndex(text, from, direction) {
  for (let i = from; i >= 0 && i < text.length; i += direction) {
    if (!/\s/.test(text[i])) return i;
  }
  return -1;
}

/** Whether a newline is a continuation rather than a statement boundary. */
function continuedLine(noStrings, index, depth) {
  if (depth > 0) return true;
  const beforeIndex = significantIndex(noStrings, index - 1, -1);
  const afterIndex = significantIndex(noStrings, index + 1, 1);
  const before = beforeIndex < 0 ? '' : noStrings[beforeIndex];
  const after = afterIndex < 0 ? '' : noStrings[afterIndex];
  return /[|,&`\\]/.test(before) || /[|&]/.test(after);
}

/**
 * Split at real statement boundaries while preserving multiline pipelines and
 * escaped newlines. Pipelines remain whole so their selector and terminator can
 * be evaluated together.
 */
export function splitSegments(command) {
  const text = String(command);
  const { noStrings, noComments } = maskViews(text);
  const ranges = [];
  let start = 0;
  let depth = 0;

  const push = (end, nextStart) => {
    ranges.push([start, end]);
    start = nextStart;
  };

  for (let i = 0; i < noStrings.length; i += 1) {
    const ch = noStrings[i];
    if (ch === '(' || ch === '{' || ch === '[') depth += 1;
    else if (ch === ')' || ch === '}' || ch === ']') depth = Math.max(0, depth - 1);

    if (ch === ';') {
      push(i, i + 1);
      continue;
    }
    if ((ch === '&' && noStrings[i + 1] === '&') || (ch === '|' && noStrings[i + 1] === '|')) {
      push(i, i + 2);
      i += 1;
      continue;
    }
    if ((ch === '\n' || ch === '\r') && !continuedLine(noStrings, i, depth)) {
      const width = ch === '\r' && noStrings[i + 1] === '\n' ? 2 : 1;
      push(i, i + width);
      i += width - 1;
    }
  }
  ranges.push([start, text.length]);

  return ranges
    .map(([from, to]) => ({
      raw: text.slice(from, to),
      noStrings: noStrings.slice(from, to),
      noComments: noComments.slice(from, to)
    }))
    .filter((segment) => segment.noStrings.trim().length > 0);
}

/**
 * Whether a command token occurs where a shell can invoke it.
 *
 * The boundary set includes newlines and `)`, because a segment joins continued
 * lines and script blocks: `for f in *; do killall chrome; done` puts `killall`
 * after a keyword, and a verb at the start of a continued physical line is still
 * the first word of its own command.
 */
function isInvocationAt(text, index) {
  const prefix = text.slice(0, index);
  const boundary = Math.max(
    prefix.lastIndexOf('|'), prefix.lastIndexOf(';'), prefix.lastIndexOf('&'),
    prefix.lastIndexOf('{'), prefix.lastIndexOf('('), prefix.lastIndexOf(')'),
    prefix.lastIndexOf('\n'), prefix.lastIndexOf('\r')
  );
  return isCommandPosition(prefix.slice(boundary + 1).trim());
}

/**
 * Whether the text between the last command boundary and a verb leaves that verb
 * in command position.
 *
 * True for nothing at all, a shell keyword, an assignment, a filesystem path, an
 * executing wrapper, or a shell's inline-code form. False for anything else,
 * which is what keeps `Write-Output taskkill chrome` as text rather than an
 * invocation. Wrapper options consume at most one following value so
 * `sudo -u root killall chrome` and `env -u FOO killall chrome` still resolve;
 * over-consuming can only make the check stricter, never weaker.
 */
function isCommandPosition(tail) {
  if (tail.length === 0) return true;
  if (PATH_PREFIX.test(tail)) return true;
  if (/^find(?:\.exe)?\b/i.test(tail) && /-exec(?:dir)?$/i.test(tail)) return true;

  let rest = tail.split(/\s+/).filter(Boolean);
  if (rest.length === 2 && rest[1] === '=' && /^\$[A-Za-z_][\w:]*$/.test(rest[0])) return true;

  for (let step = 0; rest.length > 0 && step < 12; step += 1) {
    const single = rest.length === 1 ? rest[0] : undefined;
    if (single !== undefined && (single === '=' || ENV_ASSIGNMENT.test(single) || COMMAND_KEYWORDS.has(single.toLowerCase()))) return true;
    // A path-qualified head is the same command: `/usr/bin/sudo` is `sudo`, and
    // absolute paths are the normal spelling inside scripts.
    const head = rest[0].toLowerCase().replace(/\.exe$/, '').replace(/^.*[\\/]/, '');
    if (INLINE_CODE_EXECUTABLES.includes(head) && /^-(?:c|co|com|comm|comma|comman|command)$/i.test(rest[1] ?? '')) return true;
    if (head === 'cmd' && /^\/c$/i.test(rest[1] ?? '')) return true;
    if (!EXEC_WRAPPERS.has(head)) return false;
    rest = rest.slice(1);
    while (rest.length > 0 && (WRAPPER_OPTION.test(rest[0]) || ENV_ASSIGNMENT.test(rest[0]) || PATH_TOKEN.test(rest[0]))) {
      const wasOption = rest[0].startsWith('-');
      rest = rest.slice(1);
      if (wasOption && rest.length > 0 && !rest[0].startsWith('-') && !ENV_ASSIGNMENT.test(rest[0])) rest = rest.slice(1);
    }
  }
  return rest.length === 0;
}

/** Locate a direct termination invocation. */
function findKillVerb(noStrings, noComments = noStrings, anywhere = false) {
  for (const verb of METHOD_KILL_VERBS) {
    const match = verb.re.exec(noStrings);
    if (match !== null) return verb.rule;
  }
  for (const verb of COMMAND_KILL_VERBS) {
    const match = verb.re.exec(noStrings);
    if (match === null) continue;
    if (verb.confirm !== undefined && !verb.confirm.test(noComments)) continue;
    if (anywhere || isInvocationAt(noStrings, match.index)) return verb.rule;
  }
  return undefined;
}

/**
 * Protected image names mentioned in a comment-free statement.
 *
 * Variable names are not process names: `$chrome` and the `-ErrorVariable
 * chrome` value are excluded, because a guard that refuses a notepad kill
 * whenever a parameter happens to be called `chrome` gets uninstalled. A
 * literal assigned to a variable is recovered by the flow tracker instead.
 */
function findProtectedImages(noComments, protectedImages) {
  const text = noComments.replace(VARIABLE_PARAMETER, (match) => ' '.repeat(match.length));
  const found = [];
  for (const image of protectedImages) {
    const re = new RegExp(`(?<![\\w.$-])${escapeRegex(image)}(?:\\.(?:exe|com|app))?(?![\\w.-])`, 'i');
    if (re.test(text)) found.push(image);
  }
  return found;
}

/** True when one of the known process-enumeration commands is invoked. */
function hasEnumeration(noStrings) {
  ENUMERATION_COMMAND.lastIndex = 0;
  for (const match of noStrings.matchAll(ENUMERATION_COMMAND)) {
    if (isInvocationAt(noStrings, match.index)) return true;
  }
  return false;
}

/**
 * Whether a `Where-Object`/`?` clause actually narrows a process enumeration.
 *
 * The clause must compare a process property against an operand that can
 * exclude something. `{ 1 }`, `{ $true }`, `{ $_ }`, `{ $_.ProcessName }`,
 * `{ $_.Name -ne 'zzz' }`, and `-like '*'` all leave every process in the
 * pipeline, which is the 2026-09-18 incident shape wearing a filter.
 */
function narrowsEnumeration(clause) {
  const match = NARROWING_COMPARISON.exec(clause);
  if (match === null) return false;
  const operand = match[1] ?? match[2] ?? match[3];
  return operand !== undefined && !NON_SELECTING_OPERAND.test(operand);
}

/** Whether a CIM/WMI `-Filter`/`-Query` names a process and compares it. */
function narrowsCimQuery(noComments) {
  const match = CIM_PREDICATE.exec(noComments);
  if (match === null) return false;
  return !NON_SELECTING_OPERAND.test(match[1]);
}

/** Whether an enumeration is narrowed by a PID, name, query, or pipeline filter. */
function hasEnumerationSelector(noStrings, noComments, anywhere = false) {
  if (ID_SELECTOR.test(noComments)) return true;
  if (narrowsCimQuery(noComments)) return true;
  if (/\btasklist\b[^|]{0,200}\/FI\b/i.test(noComments)) return true;
  if (/\bpgrep\b|\bSelect-String\b/i.test(noComments)) return true;

  FILTER_CLAUSE.lastIndex = 0;
  for (const match of noComments.matchAll(FILTER_CLAUSE)) {
    const rest = noComments.slice(match.index + match[0].length);
    const end = rest.search(/[|;\r\n]/);
    if (narrowsEnumeration(end < 0 ? rest : rest.slice(0, end))) return true;
  }

  const process = /\b(?:Get-Process|gps|ps)\b/ig;
  for (const match of noStrings.matchAll(process)) {
    if (!anywhere && !isInvocationAt(noStrings, match.index)) continue;
    const end = noComments.indexOf('|', match.index);
    const tail = noComments.slice(match.index + match[0].length, end < 0 ? undefined : end);
    if (/-(?:Name|Id)\b\s*(?:[:=]\s*)?(?:"[^"]{0,200}"|'[^']{0,200}'|\S{0,200})/i.test(tail)) return true;
    const tokens = tail.match(/"[^"]*"|'[^']*'|\S+/g) ?? [];
    const optionsWithValues = new Set([
      '-erroraction', '-ea', '-errorvariable', '-ev', '-warningaction', '-wa',
      '-warningvariable', '-wv', '-informationaction', '-infa',
      '-informationvariable', '-iv', '-outvariable', '-ov', '-outbuffer', '-ob',
      '-pipelinevariable', '-pv', '-computername', '-inputobject'
    ]);
    for (let i = 0; i < tokens.length; i += 1) {
      const token = tokens[i];
      const lower = token.toLowerCase();
      if (lower.startsWith('-name:') || lower.startsWith('-id:')) return true;
      if (optionsWithValues.has(lower)) {
        i += 1;
        continue;
      }
      if (lower.startsWith('-')) continue;
      return true;
    }
  }
  return false;
}

/** Wildcard/glob selectors and regular-expression process patterns. */
function hasWildcardSelector(noComments) {
  if (NAMED_WILDCARD_SELECTOR.test(noComments)) return true;
  const match = /\b(?:pkill|killall)\b([^|;&\r\n]{0,200})/i.exec(noComments);
  if (match === null) return false;
  const tokens = match[1].trim().match(/"[^"]*"|'[^']*'|\S+/g) ?? [];
  const pattern = tokens.filter((token) => !token.startsWith('-')).at(-1);
  if (pattern === undefined) return false;
  // A subshell's closing paren is syntax, not a glob: `(killall chrome)` is a
  // plain name-based kill, and only a real glob makes this a blanket selector.
  const unquoted = pattern.replace(/^(?:"([\s\S]*)"|'([\s\S]*)')$/, '$1$2').replace(/[)}]+$/, '');
  return /[.*+?^$[\]{}()|\\]/.test(unquoted);
}

/** True for the opt-in, strictly positive command-line ownership filter. */
function hasSafeScopedFilter(noComments) {
  return FILTER_CLAUSE_ANY.test(noComments)
    && POSITIVE_SAFE_FILTER.test(noComments)
    && !UNSAFE_FILTER_LOGIC.test(noComments);
}

/** Parse Unix kill arguments enough to distinguish PIDs from process groups. */
function unixKillTargets(noComments) {
  const match = /\bkill\b([^|;&\r\n]*)/i.exec(noComments);
  if (match === null) return [];
  const tokens = match[1].trim().split(/\s+/).filter(Boolean);
  let index = 0;
  if (tokens[index] === '-s' || tokens[index] === '--signal') index += 2;
  else if (/^-[A-Za-z]+$/.test(tokens[index] ?? '')) index += 1;
  else if (/^-\d+$/.test(tokens[index] ?? '') && tokens.length > 1) index += 1;
  if (tokens[index] === '--') index += 1;
  return tokens.slice(index).filter((token) => /^-?\d+$/.test(token)).map(Number);
}

function hasIdSelector(noComments) {
  if (ID_SELECTOR.test(noComments)) return true;
  if (/\b(?:pskill|tskill)(?:\.exe)?\b\s+\d+\b/i.test(noComments)) return true;
  return unixKillTargets(noComments).some((pid) => pid > 0);
}

function hasProcessGroupSelector(noComments) {
  return unixKillTargets(noComments).some((pid) => pid <= 0);
}

/** Does a protected image occur in a syntactic name-selection context? */
function hasNameBasedSelection(noStrings, noComments) {
  if (hasEnumeration(noStrings)) return true;
  return /-(?:Name|ProcessName)\b|\/IM\b|\bIMAGENAME\b|\bGetProcessesByName\b|\b(?:killall|pkill|pskill|tskill)\b|\bname\s*=|\bWin32_Process\b/i.test(noComments);
}

/**
 * Bodies of the command substitutions in a raw command: `$(...)`, `@(...)`, and
 * the POSIX backtick form.
 *
 * Only the bodies are returned, and only from outside single quotes, because
 * that is exactly what a shell executes: in `"$(date) Stop-Process -Name chrome"`
 * the substitution runs and the rest is literal text. Searching the whole string
 * instead would refuse a command that merely mentions the rule.
 *
 * PowerShell uses a backtick as an escape rather than a substitution, so a pair
 * of them can over-trigger there. A body is only reported when it also carries a
 * kill verb plus a protected image or a blanket selector, which keeps that cost
 * inside the fail-closed direction.
 */
function substitutionBodies(raw) {
  const bodies = [];
  let quote = null;
  let escaped = false;
  for (let i = 0; i < raw.length; i += 1) {
    const ch = raw[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quote === '"' && (ch === '`' || ch === '\\')) {
      // In a POSIX double-quoted string a backtick still substitutes; in
      // PowerShell it escapes the next character. A pair of backticks is the
      // substitution reading, and a body is only reported when it carries a kill
      // verb plus a target, so the PowerShell reading costs at most a rare
      // over-refusal rather than a missed kill.
      if (ch === '`' && raw.indexOf('`', i + 1) > i) {
        const close = raw.indexOf('`', i + 1);
        const body = raw.slice(i + 1, close);
        if (body.trim().length > 0) bodies.push(body);
        i = close;
        continue;
      }
      escaped = true;
      continue;
    }
    if (ch === "'" && quote === null) {
      quote = "'";
      continue;
    }
    if (ch === "'" && quote === "'") {
      quote = null;
      continue;
    }
    if (ch === '"') {
      quote = quote === '"' ? null : quote === null ? '"' : quote;
      continue;
    }
    if (quote === "'") continue;

    if (ch === '`') {
      const close = raw.indexOf('`', i + 1);
      if (close > i) {
        const body = raw.slice(i + 1, close);
        if (body.trim().length > 0) bodies.push(body);
        i = close;
      }
      continue;
    }
    if (!((ch === '$' || ch === '@') && raw[i + 1] === '(')) continue;

    let depth = 0;
    let innerQuote = null;
    let inner = null;
    let j = i + 1;
    for (; j < raw.length; j += 1) {
      const c = raw[j];
      if (innerQuote !== null) {
        if (c === innerQuote) innerQuote = null;
        continue;
      }
      if (c === "'" || c === '"') {
        innerQuote = c;
        continue;
      }
      if (c === '(') depth += 1;
      else if (c === ')') {
        depth -= 1;
        if (depth === 0) {
          inner = raw.slice(i + 2, j);
          break;
        }
      }
    }
    if (inner !== null && inner.trim().length > 0) bodies.push(inner);
    i = j;
  }
  return bodies;
}

function hasIndirectExecutor(segment) {
  const patterns = [
    /\b(?:Invoke-Expression|iex|eval)\b/ig,
    /\bcmd(?:\.exe)?\s*\/c\b/ig,
    new RegExp(`\\b(?:${INLINE_CODE_EXECUTABLES.join('|')})(?:\\.exe)?\\s+-(?:c|co|com|comm|comma|comman|command)\\b`, 'ig'),
    new RegExp(`\\b(?:${INTERPRETER_EXECUTABLES.join('|')})(?:\\.exe)?\\s+(?:-c|-e|-r|--eval|--command|eval)\\b`, 'ig')
  ];
  for (const pattern of patterns) {
    for (const match of segment.noStrings.matchAll(pattern)) {
      if (isInvocationAt(segment.noStrings, match.index)) return true;
    }
  }
  if (/(?:^|[|;&{(]\s*)&\s*\(?\s*["'][^"']*(?:Stop-Process|spps|taskkill|killall|pkill|pskill|tskill)[^"']*["']\s*\)?/i.test(segment.noComments)) return true;
  return /\b(?:Start-Process|saps)\b\s+(?:-FilePath\s+)?["']?(?:taskkill|pskill|tskill|killall|pkill)(?:\.exe)?["']?/i.test(segment.noComments);
}

/** Shorten an excerpt for the model-facing reason. */
function excerptOf(raw) {
  const flat = raw.replace(/\s+/g, ' ').trim();
  return flat.length > 120 ? `${flat.slice(0, 117)}...` : flat;
}

/** Classify text whose executable portion is hidden inside a quoted payload. */
function classifyIndirectText(text, protectedImages) {
  const verb = findKillVerb(text, text, true);
  if (verb === undefined) return undefined;
  const images = findProtectedImages(text, protectedImages);
  const blanket = hasWildcardSelector(text)
    || hasProcessGroupSelector(text)
    || (ENUMERATION_ANYWHERE.test(text) && !hasEnumerationSelector(text, text, true));
  if (images.length === 0 && !blanket) return undefined;
  return { kind: 'flag', rule: 'indirect-execution', verb, images };
}

/**
 * Classify one indirect statement: a payload hidden behind an executor
 * (`iex`, `cmd /c`, `zsh -c`, `python -c`, `Start-Process taskkill`) or inside a
 * command substitution. Each payload is searched on its own text, so literal
 * text sitting beside a substitution is not mistaken for the payload.
 */
function analyzeIndirect(segment, protectedImages) {
  if (hasIndirectExecutor(segment)) {
    const finding = classifyIndirectText(segment.noComments, protectedImages);
    if (finding !== undefined) return { ...finding, excerpt: excerptOf(segment.raw) };
  }
  for (const body of substitutionBodies(segment.raw)) {
    const finding = classifyIndirectText(body, protectedImages);
    if (finding !== undefined) return { ...finding, excerpt: excerptOf(segment.raw) };
  }
  return undefined;
}

/** Classify one direct statement. */
function analyzeSegment(segment, options, resolvedImages, inheritedBlanket = false) {
  const indirect = analyzeIndirect(segment, options.protectedImages);
  if (indirect !== undefined) return indirect;

  const verb = findKillVerb(segment.noStrings, segment.noComments);
  if (verb === undefined) return undefined;

  const images = resolvedImages;
  const excerpt = excerptOf(segment.raw);
  const groupKill = hasProcessGroupSelector(segment.noComments);
  const wildcard = inheritedBlanket || hasWildcardSelector(segment.noComments);
  const hasId = hasIdSelector(segment.noComments);

  // A named protected image outranks the blanket rules, so `Stop-Process -Name
  // 'chrome*'` reports the image it targets rather than a generic wildcard. This
  // is the precedence docs/DESIGN.md §6 documents.
  if (images.length > 0) {
    if (hasId && !hasNameBasedSelection(segment.noStrings, segment.noComments)) {
      return { kind: 'allow', rule: 'explicit-pid', verb, images: [], excerpt };
    }
    const safe = options.safeFilterAllows && hasSafeScopedFilter(segment.noComments);
    if (safe) return { kind: 'allow', rule: 'safe-scoped-filter', verb, images, excerpt };
    return { kind: 'flag', rule: 'protected-image-kill', verb, images, excerpt };
  }
  if (groupKill) return { kind: 'flag', rule: 'blanket-process-group', verb, images, excerpt };
  if (wildcard) return { kind: 'flag', rule: 'blanket-wildcard', verb, images, excerpt };
  if (!hasId && hasEnumeration(segment.noStrings) && !hasEnumerationSelector(segment.noStrings, segment.noComments)) {
    return { kind: 'flag', rule: 'blanket-enumeration', verb, images, excerpt };
  }
  return { kind: 'allow', rule: hasId ? 'explicit-pid' : 'handle-or-unprotected', verb, images, excerpt };
}

/** Decode literal PowerShell -EncodedCommand arguments. */
function encodedCommands(command) {
  const { noStrings, noComments } = maskViews(command);
  const found = [];
  // PowerShell's parameter binder accepts any unambiguous prefix, so `-Encode`,
  // `-Encoded`, and `-En` all execute the decoded command just like `-enc`. The
  // payload may also follow a backtick line continuation.
  const pattern = /\b(?:pwsh|powershell)(?:\.exe)?\b[^\r\n;]{0,300}(?:-(?:e|en|enc|enco|encod|encode|encoded|encodedcommand))\b(?:[ \t]|`[ \t]*\r?\n)+(?:"([A-Za-z0-9+/=_-]+)"|'([A-Za-z0-9+/=_-]+)'|([A-Za-z0-9+/=_-]+))/ig;
  for (const match of noComments.matchAll(pattern)) {
    const direct = isInvocationAt(noStrings, match.index);
    const hiddenByOuterExecutor = noStrings.slice(match.index, match.index + match[0].length).trim().length === 0
      && /\b(?:Invoke-Expression|iex|eval)\b|\bcmd(?:\.exe)?\s*\/c\b|\b(?:bash|sh|zsh|dash|ksh|ash|fish|pwsh|powershell)(?:\.exe)?\s+-(?:c|co|com|comm|comma|comman|command)\b/i.test(noStrings.slice(0, match.index));
    if (!direct && !hiddenByOuterExecutor) continue;
    const encoded = match[1] ?? match[2] ?? match[3];
    try {
      const normalized = encoded.replaceAll('-', '+').replaceAll('_', '/');
      const decoded = Buffer.from(normalized, 'base64').toString('utf16le').replace(/^\uFEFF/, '');
      if (decoded.trim().length > 0 && !decoded.includes('\uFFFD')) found.push(decoded);
    } catch {
      // An invalid literal is left to PowerShell; it cannot hide a runnable command.
    }
  }
  return found;
}

/**
 * Track name-selected process objects, literal command strings, and literal
 * selector values across the statements of one tool call.
 *
 * PowerShell variable names are scope-qualified (`$global:p`, `$script:p`), and
 * a variable can be introduced by `Set-Variable` as well as by `=`. A stored
 * literal is classified once, so a variable holding `'*'` marks the statement
 * that uses it as a blanket selector even though the wildcard never appears in
 * that statement's own text.
 *
 * @returns the cross-statement findings plus, per statement, the protected
 *   images that statement targets — literal names in its own text plus any
 *   resolved through a variable assigned an earlier statement.
 */
function analyzeFlow(segments, protectedImages, options, depth) {
  const processVariables = new Map();
  const commandVariables = new Map();
  const imageVariables = new Map();
  const blanketVariables = new Map();
  const findings = [];
  const imagesBySegment = [];
  const blanketBySegment = [];

  for (const segment of segments) {
    for (const [variable, images] of processVariables) {
      const escaped = escapeRegex(variable);
      const reference = `\\$(?:[A-Za-z]+:)?${escaped}`;
      const use = new RegExp(`(?:${reference}(?:\\s*\\[[^\\]]+\\])?(?:\\s*\\.\\s*\\w+)?\\s*\\.\\s*(?:Kill|CloseMainWindow|Terminate)\\s*\\(|${reference}(?:\\s*\\[[^\\]]+\\])?(?:\\s*\\.\\s*\\w+)?\\s*\\|[^\\r\\n]{0,200}(?:\\.\\s*(?:Kill|CloseMainWindow|Terminate)\\s*\\(|\\b(?:Stop-Process|spps)\\b)|(?:Stop-Process|spps)\\b[^|;]{0,200}(?:-(?:InputObject|Id)\\s+${reference}(?:\\.Id)?\\b)|(?:Invoke-CimMethod|Invoke-WmiMethod|Remove-CimInstance)\\b[^|;]{0,200}${reference}\\b)`, 'i');
      if (use.test(segment.noComments)) {
        findings.push({ kind: 'flag', rule: 'protected-image-kill', verb: 'tracked-process-handle', images, excerpt: excerptOf(segment.raw) });
      }
    }

    if (depth < MAX_INDIRECTION_DEPTH) {
      for (const [variable, value] of commandVariables) {
        const escaped = escapeRegex(variable);
        const invoke = new RegExp(`(?:\\b(?:Invoke-Expression|iex)\\b\\s+|(?:^|[|;&{(]\\s*)&\\s*)["']?\\$(?:[A-Za-z]+:)?${escaped}\\b["']?`, 'i');
        if (!invoke.test(segment.noComments)) continue;
        const nested = evaluateInternal(value, options, depth + 1);
        const names = findProtectedImages(segment.noComments, protectedImages);
        const carriesVerb = nested.findings.some((finding) => finding.verb !== undefined);
        if (nested.kind !== 'allow' || (carriesVerb && (names.length > 0 || hasWildcardSelector(segment.noComments)))) {
          findings.push({
            kind: 'flag',
            rule: 'indirect-execution',
            verb: 'variable-command',
            images: nested.kind === 'allow' ? names : nested.images,
            excerpt: excerptOf(segment.raw)
          });
        }
      }
    }

    const images = new Set(findProtectedImages(segment.noComments, protectedImages));
    let blanket = false;
    for (const [variable, names] of imageVariables) {
      if (mentionsVariable(segment.noComments, variable)) for (const name of names) images.add(name);
    }
    for (const variable of blanketVariables.keys()) {
      if (mentionsVariable(segment.noComments, variable)) blanket = true;
    }
    imagesBySegment.push([...images]);
    blanketBySegment.push(blanket);

    const assigned = new Set();
    for (const match of segment.noComments.matchAll(/\$([A-Za-z_][\w:]*)\s*=/g)) assigned.add(normalizeVariable(match[1]));
    for (const match of segment.noComments.matchAll(/\bSet-Variable\b[^|;\r\n]{0,200}?-Name\s+["']?([A-Za-z_][\w:]*)["']?/gi)) assigned.add(normalizeVariable(match[1]));
    for (const variable of assigned) {
      processVariables.delete(variable);
      commandVariables.delete(variable);
      imageVariables.delete(variable);
      blanketVariables.delete(variable);
    }

    const literal = /^\s*\$([A-Za-z_][\w:]*)\s*=\s*@?(["'])([\s\S]*?)\2@?\s*$/.exec(segment.raw);
    const unquoted = /^\s*\$([A-Za-z_][\w:]*)\s*=\s*([\w.*?]+)\s*$/.exec(segment.raw);
    const value = literal === null ? unquoted?.[2] : literal[3];
    if (value !== undefined) {
      const variable = normalizeVariable((literal ?? unquoted)[1]);
      commandVariables.set(variable, value);
      const names = findProtectedImages(value, protectedImages);
      if (names.length > 0) imageVariables.set(variable, names);
      else if (isBlanketValue(value)) blanketVariables.set(variable, true);
    }

    if (PROCESS_LOOKUP.test(segment.noStrings) && !/\b(?:Start-Process|saps)\b/i.test(segment.noStrings)) {
      const found = findProtectedImages(segment.noComments, protectedImages);
      if (found.length > 0) {
        for (const variable of assigned) processVariables.set(variable, found);
      }
    }
  }
  return { findings, imagesBySegment, blanketBySegment };
}

/** Drop a PowerShell scope qualifier so `$global:p` and `$p` are one variable. */
function normalizeVariable(variable) {
  return variable.toLowerCase().replace(VARIABLE_SCOPE, '');
}

/** Whether a statement references a tracked variable, in any scope spelling. */
function mentionsVariable(text, variable) {
  return new RegExp(`\\$(?:\\{)?(?:[A-Za-z]+:)?${escapeRegex(variable)}\\b`, 'i').test(text);
}

/**
 * Whether a stored literal is a selector that cannot pick one process.
 *
 * `$pattern = '*'; Stop-Process -Name $pattern` is `Stop-Process -Name '*'`
 * written in two statements, so the wildcard has to survive the assignment.
 */
function isBlanketValue(value) {
  const unquoted = value.trim().replace(/^(?:"([\s\S]*)"|'([\s\S]*)')$/, '$1$2');
  return unquoted.length > 0 && /[*?[]/.test(unquoted);
}

/** Model-facing explanation for one flagged statement. */
function buildReason(finding) {
  if (finding.rule === 'indirect-execution') {
    const target = finding.images.length > 0
      ? finding.images.map((image) => `"${image}"`).join(', ')
      : 'a wildcard, process group, or unfiltered process enumeration';
    return `process-guard: blocked - this indirectly executes a command that terminates ${target}. Indirection and encoded commands do not make a name-based or blanket process kill safe. Run the safe form directly: Start-Process ... -PassThru, then $p.Kill(); or target an explicit PID with -Id.`;
  }
  if (finding.rule === 'protected-image-kill') {
    const images = finding.images.map((image) => `"${image}"`).join(', ');
    return `process-guard: blocked - this terminates ${images} after selecting it by image name. That image may host the DSH GUI (http://127.0.0.1:3080), harness, or terminal, so killing it can close the UI and interrupt the session. Kill only a process you started: $p = Start-Process ... -PassThru; if (-not $p.WaitForExit(25000)) { $p.Kill() }; or target a known PID with -Id.`;
  }
  if (finding.rule === 'blanket-process-group') {
    return 'process-guard: blocked - this targets a Unix process group or every permitted process, which can terminate the DSH GUI, harness, or terminal. Target one known positive PID instead.';
  }
  return 'process-guard: blocked - this terminates a wildcard or every process returned by an unfiltered enumeration, so it can kill the DSH GUI, harness, or terminal. Target a known PID, or keep the process handle returned when you started it.';
}

function evaluateInternal(command, options, depth) {
  const segments = splitSegments(command);
  const { findings, imagesBySegment, blanketBySegment } = analyzeFlow(segments, options.protectedImages, options, depth);

  if (depth < MAX_INDIRECTION_DEPTH) {
    for (const decoded of encodedCommands(command)) {
      const nested = evaluateInternal(decoded, options, depth + 1);
      if (nested.kind !== 'allow') {
        findings.push({
          kind: 'flag',
          rule: 'indirect-execution',
          verb: 'encoded-command',
          images: nested.images,
          excerpt: excerptOf(command)
        });
      }
    }
  }

  for (const [index, segment] of segments.entries()) {
    const finding = analyzeSegment(segment, options, imagesBySegment[index], blanketBySegment[index]);
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
    kind: options.mode,
    rule: top.rule,
    images: top.images,
    excerpt: top.excerpt,
    reason: buildReason(top),
    findings
  };
}

/**
 * Evaluate one command string.
 *
 * `mode` only relabels a flagged result (`deny` or `ask`). The scoped-filter
 * exception is off by default because command-line text is not proof of process
 * ownership; deployments may opt into the documented positive filter.
 */
export function evaluateCommand(command, options = {}) {
  const protectedImages = [...new Set((options.protectedImages ?? DEFAULT_PROTECTED_IMAGES)
    .map(normalizeImage)
    .filter(Boolean))];
  return evaluateInternal(String(command), {
    protectedImages,
    mode: options.mode === 'ask' ? 'ask' : 'deny',
    safeFilterAllows: options.safeFilterAllows === true
  }, 0);
}
