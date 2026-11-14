#!/usr/bin/env python3
"""Lists every text of the desktop app that can be translated, into src/CrioFire.App/Strings/en.json.

Texts come from the XAML (Text, Content, ToolTip, Header, Title and the accessibility names, when
they are fixed English text) and from the C# code (every L.T("...") and L.T($"...")). An
interpolated text becomes a .NET format string: L.T($"Allowed {name} for {m:N0} minutes.") is
"Allowed {0} for {1:N0} minutes.", which is what translators translate.

  python build/extract-strings.py           rewrite en.json
  python build/extract-strings.py --check   fail if en.json is out of date, or a translation has
                                            texts en.json no longer lists (CI)
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = ROOT / 'src' / 'CrioFire.App'
STRINGS = APP / 'Strings'
XAML_ATTR = re.compile(r'\s(Text|Content|ToolTip|Header|Title|AutomationProperties\.Name|AutomationProperties\.HelpText)="([^"]*)"')
XML_ENTITIES = {'&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&apos;': "'"}


def xml_text(value):
    value = re.sub(r'&#x([0-9a-fA-F]+);', lambda m: chr(int(m.group(1), 16)), value)
    value = re.sub(r'&#([0-9]+);', lambda m: chr(int(m.group(1))), value)
    for entity, char in XML_ENTITIES.items():
        value = value.replace(entity, char)
    return value


def from_xaml(path):
    for match in XAML_ATTR.finditer(path.read_text(encoding='utf-8')):
        value = match.group(2)
        if value.startswith('{') or not re.search(r'[A-Za-z]{2}', value):
            continue
        yield xml_text(value)


def literal_end(s, i):
    """s[i] starts a C# string literal ($, @ prefixes allowed). Returns the index after it."""
    j = i
    verbatim = interpolated = False
    while s[j] in '$@':
        verbatim |= s[j] == '@'
        interpolated |= s[j] == '$'
        j += 1
    if s.startswith('"""', j):
        q = j
        while s[q] == '"':
            q += 1
        end = s.index('"' * (q - j), q)
        return end + (q - j)
    j += 1
    depth = 0
    while True:
        c = s[j]
        if depth == 0:
            if verbatim and s.startswith('""', j):
                j += 2
            elif not verbatim and c == '\\':
                j += 2
            elif c == '"':
                return j + 1
            elif interpolated and (s.startswith('{{', j) or s.startswith('}}', j)):
                j += 2
            elif interpolated and c == '{':
                depth = 1
                j += 1
            else:
                j += 1
        else:
            if c == '"' or (c in '$@' and re.match(r'[$@]+"', s[j:j + 4])):
                j = literal_end(s, j)
                continue
            if c == "'":
                j = s.index("'", j + 2 if s[j + 1] == '\\' else j + 1) + 1
                continue
            depth += {'{': 1, '}': -1}.get(c, 0)
            j += 1


ESCAPES = {'n': '\n', 't': '\t', 'r': '\r', '0': '\0', '\\': '\\', '"': '"', "'": "'"}


def unescape(body, verbatim):
    if verbatim:
        return body.replace('""', '"')
    out, k = [], 0
    while k < len(body):
        if body[k] == '\\' and k + 1 < len(body):
            nxt = body[k + 1]
            if nxt == 'u':
                out.append(chr(int(body[k + 2:k + 6], 16)))
                k += 6
                continue
            out.append(ESCAPES.get(nxt, nxt))
            k += 2
            continue
        out.append(body[k])
        k += 1
    return ''.join(out)


def split_hole(hole):
    """Expression, alignment and format of an interpolation hole, splitting only at top level."""
    depth, k, comma, colon = 0, 0, None, None
    while k < len(hole):
        c = hole[k]
        if c in '([{':
            depth += 1
        elif c in ')]}':
            depth -= 1
        elif c == '"' or c == '$' and hole[k + 1:k + 2] == '"':
            k = literal_end(hole, k)
            continue
        elif c == "'":
            k = hole.index("'", k + 2 if hole[k + 1] == '\\' else k + 1) + 1
            continue
        elif depth == 0 and c == '?':
            return None  # an unparenthesized conditional cannot appear here; be safe
        elif depth == 0 and c == ',' and comma is None and colon is None:
            comma = k
        elif depth == 0 and c == ':' and colon is None:
            colon = k
        k += 1
    alignment = hole[comma + 1:colon if colon is not None else len(hole)].strip() if comma is not None else None
    fmt = hole[colon + 1:] if colon is not None else None
    return alignment, fmt


def template(token):
    """The key of an L.T(...) argument: the text, or for an interpolated string its format template."""
    prefix = token[:token.index('"')]
    body = token[len(prefix) + 1:-1]
    verbatim, interpolated = '@' in prefix, '$' in prefix
    if not interpolated:
        return unescape(body, verbatim)
    out, k, n, holes = [], 0, 0, 0
    while k < len(body):
        if body.startswith('{{', k) or body.startswith('}}', k):
            out.append(body[k:k + 2])
            k += 2
            continue
        if body[k] == '{':
            end, depth = k + 1, 1
            while depth:
                c = body[end]
                if c == '"' or (c in '$@' and re.match(r'[$@]+"', body[end:end + 4])):
                    end = literal_end(body, end)
                    continue
                depth += {'{': 1, '}': -1}.get(c, 0)
                end += 1
            parts = split_hole(body[k + 1:end - 1]) or (None, None)
            alignment, fmt = parts
            out.append('{' + str(n) + (',' + alignment if alignment else '') + (':' + fmt if fmt else '') + '}')
            n += 1
            holes += 1
            k = end
            continue
        if not verbatim and body[k] == '\\':
            nxt = body[k + 1]
            if nxt == 'u':
                out.append(chr(int(body[k + 2:k + 6], 16)))
                k += 6
            else:
                out.append(ESCAPES.get(nxt, nxt))
                k += 2
            continue
        if verbatim and body.startswith('""', k):
            out.append('"')
            k += 2
            continue
        out.append(body[k])
        k += 1
    text = ''.join(out)
    # $"..." without values binds to L.T(string): the key is the plain text.
    return text.replace('{{', '{').replace('}}', '}') if holes == 0 else text


def from_cs(path):
    s = path.read_text(encoding='utf-8')
    for match in re.finditer(r'\bL\.T\(\s*', s):
        start = match.end()
        if s[start] == '"' or re.match(r'[$@]+"', s[start:start + 4]):
            yield template(s[start:literal_end(s, start)])


def collect():
    texts = []
    seen = set()
    files = sorted(APP.rglob('*.xaml')) + sorted(APP.rglob('*.cs'))
    for path in files:
        if 'obj' in path.parts or 'bin' in path.parts:
            continue
        found = from_xaml(path) if path.suffix == '.xaml' else from_cs(path)
        for text in found:
            if text not in seen:
                seen.add(text)
                texts.append(text)
    return texts


def main():
    texts = collect()
    english = {t: t for t in texts}
    target = STRINGS / 'en.json'
    rendered = json.dumps(english, ensure_ascii=False, indent=2) + '\n'
    if '--check' in sys.argv:
        problems = []
        if not target.exists() or target.read_text(encoding='utf-8') != rendered:
            problems.append('src/CrioFire.App/Strings/en.json is out of date: run python build/extract-strings.py')
        for file in sorted(STRINGS.glob('*.json')):
            if file.name == 'en.json':
                continue
            stale = [k for k in json.loads(file.read_text(encoding='utf-8')) if not k.startswith('//') and k not in english]
            if stale:
                problems.append(f'{file.name}: {len(stale)} texts the app no longer has, e.g. {stale[0]!r}')
        for p in problems:
            print(p)
        sys.exit(1 if problems else 0)
    STRINGS.mkdir(exist_ok=True)
    target.write_text(rendered, encoding='utf-8')
    print(f'{len(texts)} texts in {target.relative_to(ROOT)}')


if __name__ == '__main__':
    main()
