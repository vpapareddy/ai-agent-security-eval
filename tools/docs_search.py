from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from agent.policy import detect_prompt_injection
from app.config import get_settings

SENSITIVE_PATTERNS = {
    "api_key": "[REDACTED_KEY]",
    "password_hash": "[REDACTED_HASH]",
    "ssn_last4": "[REDACTED_SSN]",
}
STOPWORDS = {
    "and",
    "for",
    "from",
    "the",
    "that",
    "this",
    "with",
    "into",
    "your",
    "you",
    "are",
    "was",
    "were",
    "have",
    "has",
    "had",
}


def search_docs(query: str, limit: int = 3, docs_dir: Optional[Path] = None) -> dict:
    docs_root = docs_dir or get_settings().docs_dir
    terms = tokenize(query)
    results = []

    for path in sorted(docs_root.glob("*")):
        if path.suffix.lower() not in {".md", ".txt"} or not path.is_file():
            continue

        content = path.read_text(encoding="utf-8")
        lines = content.splitlines()
        filename_lower = path.stem.lower()
        heading_lower = lines[0].lower() if lines else ""
        risk_flags = detect_prompt_injection(content)
        for index, line in enumerate(lines):
            line_lower = line.lower()
            score = sum(line_lower.count(term) for term in terms)
            score += sum(filename_lower.count(term) * 3 for term in terms)
            score += sum(heading_lower.count(term) * 2 for term in terms)
            if score == 0:
                continue
            start = max(index - 1, 0)
            end = min(index + 2, len(lines))
            snippet = " ".join(part.strip() for part in lines[start:end] if part.strip())
            results.append(
                {
                    "document": path.name,
                    "snippet": redact_sensitive_content(snippet),
                    "score": score,
                    "risk_flags": risk_flags,
                    "trusted": not bool(risk_flags),
                }
            )

    results.sort(key=lambda item: (-item["score"], item["document"]))
    return {"results": results[:limit], "match_count": len(results)}


def tokenize(text: str) -> list[str]:
    return [
        token
        for token in re.findall(r"[a-zA-Z0-9_]+", text.lower())
        if len(token) > 2 and token not in STOPWORDS
    ]


def redact_sensitive_content(text: str) -> str:
    redacted = text
    for raw, replacement in SENSITIVE_PATTERNS.items():
        redacted = re.sub(raw, replacement, redacted, flags=re.IGNORECASE)
    return redacted
