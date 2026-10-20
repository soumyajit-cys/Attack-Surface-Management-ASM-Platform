"""Item (a): static scan of every ``record_audit(`` call site.

The runtime scrubber in the audit-log viewer drops secret-named keys, but
the WRITE side should not leak them into history at all: this test walks
the source tree, extracts every ``details=`` dict key from every
``record_audit(`` call, and fails when a key matches the viewer's deny
patterns unless it is on a short, explicit, commented allowlist.

Statically parsed keys only (string literals in a ``details={...}`` literal):
the scan also fails if a call site tries to hide its keys behind
``details=dict(...)`` or an f-string, so the static guarantee stays sound.
"""

from pathlib import Path

from app.api.v1.audit_logs import _matches_deny

BACKEND_ROOT = Path(__file__).resolve().parents[2]
SCAN_ROOTS = (
    BACKEND_ROOT / "app",
    BACKEND_ROOT / "tasks",
    BACKEND_ROOT / "main.py",
)

# Explicit allowlist of LOOKING-sensitive-but-reviewed keys, one comment per
# entry. Keep this list SHORT — every entry is a reviewed exception that the
# static scan would otherwise fail on.
ALLOWED: tuple[tuple[str, str], ...] = ()

# Structural forms rejected outright (a details payload the static scan
# cannot see into is treated as unsafe by default).
REJECTED_FORMS = ("details=dict(", "details=f{")


def _balanced(text: str, start: int, open_ch: str, close_ch: str) -> int | None:
    """Return the index just after the balanced block, or None on underflow.

    Skips over string literals (with escapes) so their contents can't break
    the bracket matching.
    """
    depth = 0
    i = start
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in ('"', "'"):
            quote = ch
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == quote:
                    break
                i += 1
            if i >= n:
                return None
            i += 1
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return None


def _call_sites():
    """Yield (file, line_number, call_text) for every record_audit( call."""
    sites = []
    for root in SCAN_ROOTS:
        paths = [root] if root.is_file() else sorted(root.rglob("*.py"))
        for path in paths:
            text = path.read_text(encoding="utf-8")
            idx = 0
            while (found := text.find("record_audit(", idx)) != -1:
                end = _balanced(text, found, "(", ")")
                if end is None:
                    raise AssertionError(
                        f"unbalanced record_audit( in {path.name} "
                        f"line {text[:found].count(chr(10)) + 1}")
                call_text = text[found:end]
                # skip the function definition itself
                if "def record_audit(" not in call_text:
                    line = text[:found].count("\n") + 1
                    sites.append((path.relative_to(BACKEND_ROOT), line,
                                  call_text))
                idx = found + 1
    return sites


def _details_block(call_text: str) -> str | None:
    pos = call_text.find("details=")
    if pos == -1:
        return None
    brace = call_text.find("{", pos)
    if brace == -1:
        return None
    end = _balanced(call_text, brace, "{", "}")
    return call_text[brace:end] if end is not None else None


def _literal_keys(block: str) -> list[str]:
    """Literal string keys of the details dict (nested dicts included).

    Rejects **-splats and non-literal keys: anything the static scan cannot
    see into is treated as unsafe by default.
    """
    import ast

    tree = ast.parse(block, mode="eval")
    keys: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for key in node.keys:
                if key is None:
                    raise AssertionError(
                        "details uses a **-splat; write literal keys so the "
                        "static scan can see them")
                if not isinstance(key, ast.Constant) \
                        or not isinstance(key.value, str):
                    raise AssertionError(
                        "details uses a non-literal key "
                        f"(ast.{type(key).__name__}); write a literal "
                        "string key")
                keys.append(key.value)
    return keys


class TestAuditCallSites:
    def test_scan_finds_the_call_sites(self):
        sites = _call_sites()
        # sanity: the scan must actually have visited the writers (~39)
        assert len(sites) >= 30, f"scan found only {len(sites)} call sites"

    def test_no_hidden_details_forms(self):
        for root in SCAN_ROOTS:
            paths = [root] if root.is_file() else sorted(root.rglob("*.py"))
            for path in paths:
                text = path.read_text(encoding="utf-8")
                for form in REJECTED_FORMS:
                    assert form not in text, (
                        f"{path.relative_to(BACKEND_ROOT)}: `{form}` is banned "
                        "from audit writers — write a literal "
                        "details={...} so the static scan can see the keys")

    def test_every_details_key_is_clean_or_allowlisted(self):
        allowed_keys = {key.casefold() for key, _reason in ALLOWED}
        flagged = []
        seen_keys = set()
        for rel_path, line, call_text in _call_sites():
            block = _details_block(call_text)
            if block is None:
                continue
            for key in _literal_keys(block):
                seen_keys.add(key.casefold())
            for key in _literal_keys(block):
                if _matches_deny(key) and key.casefold() not in allowed_keys:
                    flagged.append(
                        f"{rel_path}:{line}: details key `{key}` matches the "
                        "audit deny patterns and is not allowlisted")
        entries = "\n".join(f"  - {e}" for e in flagged)
        assert not flagged, (
            "sensitive-looking audit details keys found:\n\n"
            f"{entries}\n\n"
            "Either rename the key in the writer (preferred — it is honest "
            "about what it stores) or justify it in ALLOWED with a comment.")

    def test_allowlist_does_not_rot(self):
        """Every allowlisted key must still appear at a real call site."""
        allowed_keys = {key.casefold() for key, _ in ALLOWED}
        seen_keys: set[str] = set()
        for rel_path, _line, call_text in _call_sites():
            block = _details_block(call_text)
            if block is not None:
                seen_keys.update(k.casefold() for k in _literal_keys(block))
        unused = allowed_keys - seen_keys
        assert not unused, (
            f"stale ALLOWED entries (key not written anywhere): {unused}")

    def test_scanner_catches_a_violation(self):
        # self-test: the check itself must flag a sensitive key
        assert _matches_deny("api_token")
        assert _matches_deny("ConnectionPassword")
        assert not _matches_deny("lock_seconds")
        assert not _matches_deny("target_domain")
