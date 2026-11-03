#!/usr/bin/env python3
"""Check UI boundaries and their catalog references without running the application.

Install the test-only JS parser using npm ci --prefix scripts/ui-text-lint.
Checking display boundaries keeps protocol enums, CSS classes, API payloads and user
data outside the translation policy. Computed strings still need human review.
"""

import argparse
import ast
import json
import re
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[1]
SLOT = "\ufffc"
ATTRIBUTES = ("aria-label", "title", "placeholder", "alt")
VOID = set("area base br col embed hr img input link meta param source track wbr".split())
# Product names, units, protocol identifiers, and literal documentation examples.
TECHNICAL = {
    "BOLT12 Pay", "BOLT12", "BOLT11", "BIP353", "LNURL", "LND", "NWC", "Nostr",
    "BOLT12 Pay Server", "⚡ Lightning BOLT12 Pay", "bolt12",
    "WebLN", "Cloudflare", "Umbrel", "StartOS", "DNS", "TXT", "HTTPS", "QR",
    "sats", "sat", "msat", "msats", "lnbc...", "lno...", "lnurl1...",
    "bolt12@example.com", "lnurl@yourdomain.com", "user@domain",
    "Apps → lightning → data → lnd → lnd.conf",
    "[protocol] protocol.custom-message=513 protocol.custom-nodeann=39 protocol.custom-init=39",
    '"bitcoin:?lno=<offer>"', "(BOLT11)",
    "get_info: • get_balance: • pay_invoice:",
}
FAMILIES = {
    ("pay", "contact.type." + SLOT): {
        "contact.type." + suffix for suffix in ("lightning_address", "bolt12", "lnurl", "bip353", "nostr", "node", "other")
    },
    ("pay", "label.period_" + SLOT): {"label.period_day", "label.period_week", "label.period_month"},
    ("pay", "setup.repair_record." + SLOT): {"setup.repair_record.created", "setup.repair_record.exists"},
    ("console", "setup.repair_record." + SLOT): {"setup.repair_record.created", "setup.repair_record.exists"},
}


def human_text(text):
    if text.strip() == "v" + SLOT:  # Version indicator, e.g. v0.3.19.
        return False
    text = " ".join(text.replace(SLOT, "").split())
    if re.fullmatch(r"[a-z\d.-]*\.user\._bitcoin-payment\.[a-z\d.-]*", text):
        return False
    if not any(c.isalpha() for c in text):
        return False
    if text.strip(" :[]•⚡") in TECHNICAL or text in TECHNICAL:
        return False
    if re.fullmatch(r"(?:\d+(?:[.kK]\d*)?\s*(?:sats?|msats?|×)|[\d.]+×)", text):
        return False
    if re.fullmatch(r"(?:https?://|wss://|bitcoin:|lightning:|/)[\w\-./@:?=&\"<>]*", text):
        return False
    return True


class Checker:
    def __init__(self, catalogs):
        self.catalogs = catalogs
        self.errors = []
        self.units = []
        self.pwa_labels = {}

    def check(self, path, scope, line, kind, value):
        location = f"{path}:{line}"
        if kind == "key":
            if value not in self.catalogs.get(scope, {}):
                self.errors.append(f"{location}: unknown {scope} key {value!r}")
        elif kind == "raw" and human_text(value):
            self.errors.append(f"{location}: UI text requires a {scope} key: {' '.join(value.split())!r}")
        elif kind == "family":
            if scope == "login" and value == "login." + SLOT:
                return  # Each loginText() call is checked against login.<argument>.
            family = FAMILIES.get((scope, value))
            if family is None:
                self.errors.append(f"{location}: define the supported keys for dynamic {scope} key {value!r}")
            for key in family or ():
                self.check(path, scope, line, "key", key)
        elif kind == "html":
            self.html(path, scope, value, line, inspect_events=False)
        elif kind == "syntax":
            self.errors.append(f"{location}: invalid JavaScript: {value}")

    def html(self, path, scope, source, line=1, inspect_events=True):
        parser = Markup(self, str(path), scope, line, inspect_events)
        parser.feed(source)
        parser.close()

    def javascript(self, path, scope, source, line=1):
        self.units.append({"pwaLabels": self.pwa_labels.get(scope, {}), "location": {"path": str(path), "scope": scope, "line": line}, "source": source})

    def finish(self):
        if self.units:
            proc = subprocess.run(
                ["node", str(Path(__file__).parent / "ui-text-lint/scan.cjs")],
                input=json.dumps(self.units), text=True, capture_output=True, check=False,
            )
            if proc.returncode:
                raise RuntimeError("Cannot analyze JavaScript. Run npm ci --prefix scripts/ui-text-lint.\n" + proc.stderr)
            self.units.clear()
            for entry in json.loads(proc.stdout):
                self.check(**entry)
        return sorted(set(self.errors))


class Markup(HTMLParser):
    def __init__(self, checker, path, scope, line, inspect_events):
        super().__init__()
        self.checker, self.path, self.scope = checker, path, scope
        self.base_line, self.inspect_events = line, inspect_events
        self.stack = []

    def check(self, kind, value):
        self.checker.check(self.path, self.scope, self.base_line + self.getpos()[0] - 1, kind, value)

    def handle_starttag(self, tag, pairs):
        attrs = dict(pairs)
        if tag == "script" and attrs.get("src") == "/pwa-install.js":
            self.checker.pwa_labels[self.scope] = {k: v for k, v in pairs if k.startswith("data-label-")}
        for attr in ATTRIBUTES:
            if attrs.get(attr) and not attrs.get(f"data-i18n-{attr}"):
                self.check("raw", attrs[attr])
        for attr, value in pairs:
            if attr == "data-i18n" or attr in {"data-i18n-" + a for a in ATTRIBUTES} or attr.startswith("data-label-"):
                if value and SLOT not in value:
                    self.check("key", value)
            if self.inspect_events and attr.startswith("on") and value:
                self.checker.javascript(self.path, self.scope, value, self.base_line + self.getpos()[0] - 1)
        if tag not in VOID:
            self.stack.append((tag, "data-i18n" in attrs))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break

    def handle_data(self, text):
        if not text.strip():
            return
        tags = [entry[0] for entry in self.stack]
        if "script" in tags:
            if self.inspect_events:
                self.checker.javascript(self.path, self.scope, text, self.base_line + self.getpos()[0] - 1)
        elif "style" not in tags and not any(marked for _, marked in self.stack):
            self.check("raw", text)


def server_fragments(checker, root):
    path = Path("app/backend/app.py")
    tree = ast.parse((root / path).read_text())
    active = {
        "public_index_page": ("landing",), "public_alias_page": ("alias",),
        "_public_description_html": ("landing", "alias"), "_public_amount_html": ("landing", "alias"),
    }

    def visit(node, scopes):
        if isinstance(node, ast.JoinedStr):
            text = "".join(part.value if isinstance(part, ast.Constant) else SLOT for part in node.values)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value
        else:
            for child in ast.iter_child_nodes(node):
                visit(child, scopes)
            return
        if re.search(r"<(?:!doctype|[a-z][a-z0-9]*\b)[^>]*>", text, re.I):
            for scope in scopes:
                checker.html(path, scope, text, node.lineno)

    for fn in tree.body:
        if getattr(fn, "name", None) in active:
            visit(fn, active[fn.name])
            # F-string data-i18n="{subline_key}" gets its possible keys in Python.
            for node in ast.walk(fn):
                if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == "subline_key" for t in node.targets
                ):
                    for key in ast.walk(node.value):
                        if isinstance(key, ast.Constant) and isinstance(key.value, str):
                            for scope in active[fn.name]:
                                checker.check(path, scope, node.lineno, "key", key.value)


def android(checker, root):
    main = root / "android-companion/app/src/main"
    resources = {el.attrib["name"] for el in ElementTree.parse(main / "res/values/strings.xml").getroot()}
    for path in main.rglob("*.java"):
        source = path.read_text()
        for match in re.finditer(r"\bR\.string\.(\w+)", source):
            if match[1] not in resources:
                checker.errors.append(f"{path.relative_to(root)}:{source.count(chr(10), 0, match.start())+1}: "
                                      f"unknown Android string resource {match[1]}")
        # Follow multiline calls and ternaries. Android contracts use R.string.* or
        # runtime data (host name, intent target); literal UI text belongs in XML.
        for match in re.finditer(r'\b(?:setText|setHint|setTitle|setMessage|setContentDescription|setError|'
                                r'makeText|text|showError)\s*\(([^;]*?)\)\s*[.;]', source, re.S):
            for word in re.findall(r'"((?:\\.|[^"\\])*)"', match[1]):
                checker.check(path.relative_to(root), "Android resource", source.count("\n", 0, match.start())+1, "raw", word)
    ns = "{http://schemas.android.com/apk/res/android}"
    for path in [main / "AndroidManifest.xml", *(main/"res").glob("layout*/*.xml")]:
        for el in ElementTree.parse(path).iter():
            for attr in ("text", "hint", "label", "contentDescription", "title"):
                value = el.get(ns+attr)
                if value and not value.startswith(("@", "?")):
                    checker.check(path.relative_to(root), "Android resource", 1, "raw", value)


def check_repository(root):
    catalogs = {p.parent.name: json.loads(p.read_text()) for p in (root/"app/i18n").glob("*/en.json")}
    checker = Checker(catalogs)
    frontend = root / "app/frontend"
    for path in sorted(frontend.glob("*/*.html")):
        source = path.read_text()
        match = re.search(r'''Bolt12I18n\.use\(\s*["']([^"']+)["']\s*\)''', source)
        if not match or match[1] not in catalogs:
            checker.errors.append(f"{path.relative_to(root)}: choose a registered translation catalog")
            continue
        checker.html(path.relative_to(root), match[1], source)
    # The shared installation controller can use keys supplied by either page's script tag.
    path = Path("app/frontend/admin/pwa-install.js")
    for scope in ("pay", "console"):
        checker.javascript(path, scope, (root / path).read_text())
    server_fragments(checker, root)
    android(checker, root)
    return checker.finish()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        errors = check_repository(args.root)
    except (OSError, RuntimeError, ValueError) as error:
        sys.exit(str(error))
    if errors:
        sys.exit("\n".join(errors))
    print("UI text and translation keys checked.")
