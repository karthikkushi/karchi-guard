"""Claude Code permission rules: would a tool call be blocked, asked about, or run without asking?

Trimmed copy of Rogue Drill's matcher (github.com/karthikkushi/nova-harbor, MIT, same author).
It follows Claude Code's documented order: deny, then ask, then allow. Hook scripts are never run
here, so a hook that may apply makes the answer UNKNOWN, never safe.
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass
from pathlib import Path

BLOCKED = "blocked"
ASKS = "asks"
RUNS = "runs"
UNKNOWN = "unknown"

_RULE = re.compile(r"([A-Za-z0-9_.:\-*]+)(?:\((.*)\))?\Z", re.DOTALL)
_SEPARATORS = re.compile(r"&&|\|\||;|\|&|\||&|\n")
# Commands that run other commands. Claude Code treats some of them specially; we do not guess.
_INDIRECT = {
    "timeout", "time", "nice", "nohup", "stdbuf", "command", "xargs", "sudo", "env", "bash", "sh", "zsh",
    "watch", "setsid", "ionice", "flock", "npx", "docker", "direnv", "devbox", "mise",
}
_SAFE_PATH_RULE = re.compile(r"[A-Za-z0-9_.\-/*]+\Z")


@dataclass(frozen=True)
class Rule:
    tool: str  # "" when the rule text could not be parsed
    specifier: str | None
    raw: str


@dataclass(frozen=True)
class Settings:
    deny: tuple[Rule, ...]
    ask: tuple[Rule, ...]
    allow: tuple[Rule, ...]
    hook_matchers: tuple[str, ...]  # PreToolUse hooks only
    mode: str | None
    files: tuple[Path, ...]


def parse_rule(text: str) -> Rule:
    match = _RULE.match(text)
    return Rule(match.group(1), match.group(2), text) if match else Rule("", None, text)


def load(paths: list[Path]) -> Settings | None:
    """Merge the settings files that exist. None when there are none. ValueError on bad JSON."""
    files = [p for p in paths if p.is_file()]
    if not files:
        return None
    rules: dict[str, list[Rule]] = {"deny": [], "ask": [], "allow": []}
    hooks: list[str] = []
    mode = None
    for path in files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise ValueError(f"{path}: cannot read settings: {error}") from error
        permissions = data.get("permissions", {}) if isinstance(data, dict) else {}
        permissions = permissions if isinstance(permissions, dict) else {}
        for kind in rules:
            entries = permissions.get(kind, [])
            rules[kind] += [parse_rule(e) for e in entries if isinstance(e, str)] if isinstance(entries, list) else []
        if isinstance(permissions.get("defaultMode"), str):
            mode = permissions["defaultMode"]
        groups = data.get("hooks", {}) if isinstance(data, dict) else {}
        for group in groups.get("PreToolUse", []) if isinstance(groups, dict) else []:
            if isinstance(group, dict):
                hooks.append(str(group.get("matcher", "")))
    return Settings(tuple(rules["deny"]), tuple(rules["ask"]), tuple(rules["allow"]), tuple(hooks), mode, tuple(files))


def decide(settings: Settings, tool: str, text: str = "") -> tuple[str, str]:
    """What Claude Code does with this tool call: (BLOCKED|ASKS|RUNS|UNKNOWN, reason)."""
    matched: dict[str, str] = {}
    uncertain: list[str] = []
    for kind, rules in (("deny", settings.deny), ("ask", settings.ask), ("allow", settings.allow)):
        for rule in rules:
            outcome = _rule_matches(kind, rule, tool, text)
            if outcome is None:
                uncertain.append(rule.raw)
            elif outcome and kind not in matched:
                matched[kind] = rule.raw
    if "deny" in matched:
        return BLOCKED, f"deny rule {matched['deny']}"
    if any(_hook_applies(m, tool) is not False for m in settings.hook_matchers):
        return UNKNOWN, "a PreToolUse hook may stop it (this check never runs hooks)"
    if "ask" in matched:
        return ASKS, f"ask rule {matched['ask']}"
    if uncertain:
        return UNKNOWN, f"could not interpret rule {uncertain[0]}"
    if settings.mode == "bypassPermissions":
        return RUNS, "defaultMode is bypassPermissions, so nothing asks you first"
    if "allow" in matched:
        return RUNS, f"allowed without asking by {matched['allow']}"
    if tool == "Read":
        return RUNS, "Claude Code reads files without asking by default"
    return ASKS, "Claude Code asks you first"


def _rule_matches(kind: str, rule: Rule, tool: str, text: str) -> bool | None:
    """True/False when sure, None when this check cannot tell."""
    if not rule.tool:
        return None
    if tool.startswith("mcp__"):
        server = "__".join(tool.split("__")[:2])
        return rule.tool in (tool, server, server + "__*")
    if rule.tool == tool:
        return _bash_match(rule, text) if tool == "Bash" else _read_match(rule, text)
    if rule.tool == "Read" and tool == "Bash" and kind in ("deny", "ask"):
        # Claude Code applies Read rules to file commands such as cat, head and tail in Bash.
        outcomes = [_read_match(rule, path) for path in _bash_read_paths(text)]
        if any(o is True for o in outcomes):
            return True
        return None if any(o is None for o in outcomes) else False
    return False


def _subcommands(command: str) -> list[str]:
    return [part.strip() for part in _SEPARATORS.split(command) if part.strip()]


def _bash_regex(specifier: str) -> re.Pattern:
    if specifier.endswith(":*"):
        specifier = specifier[:-2] + " *"
    if "*" not in specifier:
        return re.compile(re.escape(specifier) + r"\Z")
    if specifier.endswith(" *") and specifier.count("*") == 1:
        return re.compile(re.escape(specifier[:-2]) + r"(?: .*)?\Z", re.DOTALL)
    return re.compile(".*".join(re.escape(part) for part in specifier.split("*")) + r"\Z", re.DOTALL)


def _bash_match(rule: Rule, command: str) -> bool | None:
    if rule.specifier in (None, "*"):
        return True
    pattern = _bash_regex(rule.specifier)
    parts = _subcommands(command)
    if pattern.match(command.strip()) or any(pattern.match(part) for part in parts):
        return True
    if any(part.split()[0] in _INDIRECT for part in parts):
        return None
    return False


def _bash_read_paths(command: str) -> list[str]:
    paths: list[str] = []
    for part in _subcommands(command):
        try:
            words = shlex.split(part)
        except ValueError:
            continue
        if words and words[0] in ("cat", "head", "tail"):
            paths += [w for w in words[1:] if not w.startswith("-")]
    return paths


def _read_match(rule: Rule, path: str) -> bool | None:
    spec = rule.specifier
    if spec in (None, "*", "**"):
        return True
    if not _SAFE_PATH_RULE.match(spec) or spec.startswith("/"):
        return None  # ~/, // and /path anchors, and unusual characters: not interpreted here
    target = path[2:] if path.startswith("./") else path
    anchored = spec.startswith("./") or "/" in spec.rstrip("/")
    body = spec[2:] if spec.startswith("./") else spec
    regex, i = "", 0
    while i < len(body):
        if body.startswith("**/", i):
            regex, i = regex + "(?:.*/)?", i + 3
        elif body.startswith("**", i):
            regex, i = regex + ".*", i + 2
        elif body[i] == "*":
            regex, i = regex + "[^/]*", i + 1
        else:
            regex, i = regex + re.escape(body[i]), i + 1
    prefix = "" if anchored else "(?:.*/)?"
    return re.fullmatch(prefix + regex + "(?:/.*)?", target) is not None


def _hook_applies(matcher: str, tool: str) -> bool | None:
    if matcher in ("", "*"):
        return True
    if re.fullmatch(r"[A-Za-z0-9_\- ,|]+", matcher):
        return tool in [name.strip() for name in re.split(r"[|,]", matcher)]
    try:
        return re.search(matcher, tool) is not None
    except re.error:
        return None
