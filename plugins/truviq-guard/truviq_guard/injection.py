"""Prompt-injection and hidden-text detection (G-OBF-001, G-INJ-*).

`scan(text)` returns three lists:
  obf    hidden / invisible text            -> G-OBF-001
  inj    clear instructions aimed at an AI  -> G-INJ-00x (caller picks the ID)
  weak   suspicious but unclear snippets    -> sent to the LLM classifier if enabled
"""
from __future__ import annotations

import re

TAG_CHARS = re.compile("[\U000E0000-\U000E007F]+")
BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
ZERO_WIDTH_RUN = re.compile("[\u200b\u200c\u200d\u2060\ufeff]{3,}")
VARIATION_RUN = re.compile("[\ufe00-\ufe0f\U000E0100-\U000E01EF]{8,}")

AI = r"(?:ai|a\.i\.|llm|language\s+model|(?:coding\s+|code\s+|ai\s+)?(?:agent|assistant)s?|claude|copilot|gemini|cursor|chatgpt|gpt-?\d*|codex|bot)"
SENSITIVE = (r"(?:curl|wget|rm\s+-rf|exfiltrat\w*|leak\w*|steal\w*|upload\w*|send\w*|post\s+(?:it|them|the)|\.env\b|ssh|id_rsa|api[\s_-]?keys?|"
             r"tokens?|secrets?|passwords?|credentials?|private\s+keys?|disable\w*|--no-verify|chmod\s+777|base64)")

STRONG = [
    (re.compile(r"\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+|the\s+|your\s+|of\s+)*"
                r"(?:previous|prior|above|earlier|preceding|system|original|existing)\s+"
                r"(?:instructions?|prompts?|rules|directions|directives|guidelines|context|messages?|questions?|requests?|"
                r"conversations?|commands?|tasks?|constraints?|restrictions?|limitations?|policies|polic(?:y)|guardrails?|"
                r"safety|text|inputs?|answers?|responses?)"
                r"|\b(?:ignore|disregard|forget)\s+(?:all\s+of\s+|all\s+)?(?:everything|anything)\s+(?:above|before|earlier|you\s+were\s+told)", re.I),
     "tells the AI to ignore its instructions"),
    (re.compile(r"\b(?:leak|exfiltrat\w*|steal|harvest)\s+(?:out\s+)?(?:all\s+|the\s+|my\s+|your\s+|any\s+|every\s+|of\s+)*"
                r"(?:secrets?|credentials?|api[\s_-]?keys?|access\s+keys?|tokens?|passwords?|private\s+keys?|ssh\s+keys?|\.env\b|"
                r"env(?:ironment)?\s+(?:vars?|variables?)|keys?\b)"
                r"|\bdump\s+(?:out\s+)?(?:all\s+|the\s+|my\s+|your\s+|any\s+|every\s+|of\s+)*"
                r"(?:secrets?|credentials?|api[\s_-]?keys?|passwords?|private\s+keys?|ssh\s+keys?|\.env\b)", re.I),
     "asks the AI to leak secrets or credentials"),
    (re.compile(r"\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention\s+(?:this\s+)?to|mention|reveal\s+(?:this\s+)?to|alert|notify|show\s+(?:this\s+)?to)\s+"
                r"(?:the\s+)?(?:user|developer|human|operator|owner)", re.I),
     "tells the AI to hide something from the user"),
    (re.compile(r"\bwithout\s+(?:telling|asking|informing|notifying|alerting|confirming\s+with)\s+(?:the\s+)?(?:user|developer|human|operator)", re.I),
     "tells the AI to act without telling the user"),
    (re.compile(r"<\|im_start\|>|<\|im_end\|>|\[/?INST\]|<<SYS>>|<\|system\|>|<\|endoftext\|>|<\|start_header_id\|>", re.I),
     "contains chat-template control tokens"),
    (re.compile(r"\byou\s+are\s+now\s+(?:in\s+)?(?:a\s+|an\s+|the\s+)?(?:dan|developer\s+mode|maintenance\s+mode|god\s+mode|jailbr\w+|unrestricted|unfiltered|no\s+longer)", re.I),
     "tries to switch the AI into a different mode"),
    (re.compile(r"\bif\s+you\s+are\s+an?\s+" + AI + r"\b", re.I),
     "addresses AI readers directly"),
    (re.compile(r"\b(?:attention|note|important|instructions?|message|reminder)?\s*(?:to|for)?\s*(?:all\s+)?" + AI +
                r"\s*[,:;.!-]{0,3}\s*(?:you\s+)?(?:must|should|need\s+to|are\s+(?:required|instructed)\s+to|have\s+to)\s+"
                r"(?:\S+\s+){0,6}?[`'\"(]*" + SENSITIVE, re.I),
     "instructs AI agents to perform a sensitive action"),
    (re.compile(r"(?im)^\s*(?:system|assistant)\s*:\s*(?:you\s+(?:are|must|will)|ignore|new\s+instructions|from\s+now\s+on)"),
     "fake system/assistant message"),
]

AI_RX = re.compile(r"\b" + AI + r"\b", re.I)
SENSITIVE_RX = re.compile(SENSITIVE, re.I)
IMPERATIVE_RX = re.compile(r"\b(?:run|execute|must|should|please|before|always|first|then|add|include|call|use)\b", re.I)


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _snippet(text: str, start: int, end: int, pad: int = 80) -> str:
    s = text[max(0, start - pad): min(len(text), end + pad)]
    return re.sub(r"\s+", " ", s).strip()[:400]


def _html_comments(text: str, limit: int = 2000):
    """Yield (start, inner) for each <!-- ... --> in linear time (no regex backtracking)."""
    pos = 0
    for _ in range(limit):
        start = text.find("<!--", pos)
        if start < 0:
            return
        end = text.find("-->", start + 4)
        if end < 0:
            return
        yield start, text[start + 4:end][:4000]
        pos = end + 3


def decode_tags(s: str) -> str:
    return "".join(chr(ord(c) - 0xE0000) for c in s if 0x20 <= ord(c) - 0xE0000 < 0x7F)


def scan(text: str) -> dict:
    obf, inj, weak = [], [], []
    if not text:
        return {"obf": obf, "inj": inj, "weak": weak}

    for m in TAG_CHARS.finditer(text):
        hidden = decode_tags(m.group(0))
        obf.append({"severity": "CRITICAL", "line": _line(text, m.start()),
                    "summary": f"invisible Unicode tag characters spelling: {hidden[:120]!r}", "snippet": hidden[:400]})
    for m in BIDI.finditer(text):
        obf.append({"severity": "HIGH", "line": _line(text, m.start()),
                    "summary": "bidirectional control character (can make code read differently than it runs)",
                    "snippet": _snippet(text, m.start(), m.end(), 40)})
        break
    for rx, why in ((ZERO_WIDTH_RUN, "run of zero-width characters"), (VARIATION_RUN, "run of variation selectors (possible hidden data)")):
        m = rx.search(text)
        if m:
            obf.append({"severity": "MEDIUM", "line": _line(text, m.start()), "summary": why,
                        "snippet": _snippet(text, m.start(), m.end(), 40)})

    for start, inner in _html_comments(text):
        if (AI_RX.search(inner) and (SENSITIVE_RX.search(inner) or IMPERATIVE_RX.search(inner))) or \
                any(rx.search(inner) for rx, _ in STRONG):
            inj.append({"severity": "CRITICAL", "line": _line(text, start),
                        "summary": "hidden HTML comment with instructions for AI agents",
                        "snippet": _snippet(inner, 0, len(inner), 0)})

    for rx, why in STRONG:
        m = rx.search(text)
        if m and not any(f["line"] == _line(text, m.start()) and f["severity"] == "CRITICAL" for f in inj):
            inj.append({"severity": "HIGH", "line": _line(text, m.start()), "summary": why,
                        "snippet": _snippet(text, m.start(), m.end())})

    if not inj:
        for n, m in enumerate(AI_RX.finditer(text)):
            if n >= 300:  # bounded work on huge or adversarial text
                break
            window = text[max(0, m.start() - 150): m.end() + 150]
            if SENSITIVE_RX.search(window) and IMPERATIVE_RX.search(window):
                weak.append(_snippet(text, m.start(), m.end(), 200))
                if len(weak) >= 5:
                    break
        if not weak:
            for m in re.finditer(r"\bexfiltrat\w*|\bsend\s+(?:the\s+|all\s+|your\s+)?(?:secrets?|tokens?|keys?|credentials?|\.env)\b", text, re.I):
                weak.append(_snippet(text, m.start(), m.end(), 200))
                break
    return {"obf": obf, "inj": inj, "weak": weak}
