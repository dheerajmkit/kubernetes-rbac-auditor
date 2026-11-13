"""Minimal YAML-subset parser for Kubernetes manifests.

Supports mappings, sequences, nested blocks by indentation, quoted and
plain scalars, integers, booleans, null, flow lists like ["a", "b"],
comments, and --- document separators. Not a full YAML implementation —
just enough for RBAC manifests.
"""


def _strip_comment(line):
    in_single = in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == '#' and not in_single and not in_double \
                and (i == 0 or line[i - 1] in ' \t'):
            return line[:i].rstrip()
    return line


def _split_flow(inner):
    parts, buf, in_single, in_double, depth = [], "", False, False, 0
    for ch in inner:
        if ch == "'" and not in_double:
            in_single = not in_single
            buf += ch
        elif ch == '"' and not in_single:
            in_double = not in_double
            buf += ch
        elif ch in '[{' and not in_single and not in_double:
            depth += 1
            buf += ch
        elif ch in ']}' and not in_single and not in_double:
            depth -= 1
            buf += ch
        elif ch == ',' and not in_single and not in_double and depth == 0:
            parts.append(buf)
            buf = ""
        else:
            buf += ch
    if buf.strip():
        parts.append(buf)
    return parts


def _scalar(text):
    text = text.strip()
    if text in ('', '~', 'null', 'Null', 'NULL'):
        return None
    if text in ('true', 'True', 'TRUE'):
        return True
    if text in ('false', 'False', 'FALSE'):
        return False
    if len(text) >= 2 and text[0] == text[-1] and text[0] in '"\'':
        return text[1:-1]
    if text.startswith('[') and text.endswith(']'):
        inner = text[1:-1].strip()
        if not inner:
            return []
        return [_scalar(part) for part in _split_flow(inner)]
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    return text


def _split_kv(line):
    for i, ch in enumerate(line):
        if ch == ':' and (i + 1 == len(line) or line[i + 1] in ' \t'):
            return line[:i].strip(), line[i + 1:].strip()
    return None, None


class _Lines:
    def __init__(self, text):
        self.items = []
        for raw in text.splitlines():
            if raw.strip() in ('', '---'):
                continue
            line = _strip_comment(raw)
            if line.strip() == '':
                continue
            indent = len(line) - len(line.lstrip(' '))
            self.items.append((indent, line.strip()))
        self.pos = 0


def _parse_block(lines, indent):
    if lines.pos >= len(lines.items):
        return None
    ind, text = lines.items[lines.pos]
    if ind < indent:
        return None
    if text.startswith('- ') or text == '-':
        return _parse_seq(lines, ind)
    if _split_kv(text)[0] is not None:
        return _parse_map(lines, ind)
    lines.pos += 1
    return _scalar(text)


def _parse_map(lines, indent):
    result = {}
    while lines.pos < len(lines.items):
        ind, text = lines.items[lines.pos]
        if ind != indent or text.startswith('- '):
            break
        key, value = _split_kv(text)
        if key is None:
            break
        lines.pos += 1
        if value:
            result[key] = _scalar(value)
        elif lines.pos < len(lines.items) \
                and (lines.items[lines.pos][0] > indent
                     or (lines.items[lines.pos][0] == indent
                         and lines.items[lines.pos][1].startswith('- '))):
            # Nested block, or a block sequence at the same indent as
            # the key (valid YAML: "rules:\n- ...").
            result[key] = _parse_block(lines, lines.items[lines.pos][0])
        else:
            result[key] = None
    return result


def _parse_seq(lines, indent):
    result = []
    while lines.pos < len(lines.items):
        ind, text = lines.items[lines.pos]
        if ind != indent or not (text.startswith('- ') or text == '-'):
            break
        item_text = text[1:].strip()
        if item_text == '':
            lines.pos += 1
            if lines.pos < len(lines.items) \
                    and lines.items[lines.pos][0] > indent:
                result.append(_parse_block(lines, lines.items[lines.pos][0]))
            else:
                result.append(None)
            continue
        if _split_kv(item_text)[0] is not None:
            lines.items[lines.pos] = (indent + 2, item_text)
            result.append(_parse_map(lines, indent + 2))
        else:
            lines.pos += 1
            result.append(_scalar(item_text))
    return result


def parse_yaml(text):
    """Parse YAML text into a list of documents."""
    chunks, current = [], []
    for raw in text.splitlines():
        if raw.strip() == '---':
            chunks.append('\n'.join(current))
            current = []
        else:
            current.append(raw)
    chunks.append('\n'.join(current))
    docs = []
    for chunk in chunks:
        if not chunk.strip():
            continue
        lines = _Lines(chunk)
        while lines.pos < len(lines.items):
            docs.append(_parse_block(lines, lines.items[lines.pos][0]))
    return docs
