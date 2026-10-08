"""Rule-based / heuristic analysis of an email.

IMPORTANT: everything in this module is a transparent rule, NOT the ML model.
The UI labels it "rule-based" so it is never confused with the model's prediction.

The keyword lexicon and URL pattern are exported (see `client_config`) so the browser can
compute the same real-time statistics while the user types.
"""
import re
from urllib.parse import urlsplit

# ----------------------------------------------------------------------------
# Lexicon: category -> list of (phrase_or_regex, severity)
# severity "high" = strong signal (red), "medium" = suspicious wording (yellow).
# Plain phrases are converted to regexes (spaces -> \s+, apostrophes tolerant).
# Entries starting with "re:" are raw regexes valid in both Python and JavaScript.
# ----------------------------------------------------------------------------
LEXICON = {
    "urgency": [
        ("act now", "high"), ("limited time", "high"), ("final notice", "high"),
        ("within 24 hours", "high"), ("within 48 hours", "medium"), ("immediate action", "high"),
        ("urgent", "medium"), ("urgently", "medium"), ("immediately", "medium"),
        ("right away", "medium"), ("asap", "medium"), ("expires", "medium"), ("expiring", "medium"),
        ("last chance", "high"), ("final warning", "high"), ("hurry", "medium"),
        ("don't miss", "medium"), ("today only", "medium"), ("act fast", "medium"),
        ("respond now", "medium"), ("before it's too late", "high"),
    ],
    "prize_money": [
        ("you have won", "high"), ("you've won", "high"), ("winner", "high"), ("won", "medium"),
        ("congratulations", "medium"), ("prize", "high"), ("lottery", "high"), ("jackpot", "high"),
        ("cash prize", "high"), ("free gift", "high"), ("gift card", "high"), ("inheritance", "high"),
        ("100% free", "high"), ("make money", "high"), ("earn money", "high"), ("wire transfer", "high"),
        ("cash", "medium"), ("free", "medium"), ("reward", "medium"), ("claim", "medium"),
        ("million", "medium"), ("bonus", "medium"), ("refund", "medium"), ("guaranteed", "medium"),
        ("bitcoin", "medium"), ("work from home", "medium"),
        ("re:[$₹£€]\\s?\\d[\\d,]*(?:\\.\\d+)?(?:\\s?(?:k|m|million|lakhs?|crore)\\b)?", "medium"),
    ],
    "phishing": [
        ("verify your account", "high"), ("verify your identity", "high"),
        ("confirm your identity", "high"), ("account has been suspended", "high"),
        ("account suspended", "high"), ("account will be closed", "high"), ("account locked", "high"),
        ("unusual activity", "high"), ("update your payment", "high"), ("billing information", "high"),
        ("social security", "high"), ("click here", "high"),
        ("suspicious activity", "medium"), ("security alert", "medium"), ("password", "medium"),
        ("login", "medium"), ("log in", "medium"), ("sign in", "medium"),
        ("payment details", "medium"), ("credit card", "medium"), ("bank account", "medium"),
        ("otp", "medium"), ("click the link", "medium"), ("click below", "medium"),
        ("confirm your", "medium"), ("dear customer", "medium"), ("dear user", "medium"),
        ("dear account holder", "medium"), ("kyc", "medium"), ("verify", "medium"),
    ],
    "promotional": [
        ("buy now", "medium"), ("shop now", "medium"), ("order now", "medium"),
        ("special offer", "medium"), ("limited offer", "medium"), ("exclusive deal", "medium"),
        ("promo code", "medium"), ("free shipping", "medium"), ("save up to", "medium"),
        ("discount", "medium"), ("coupon", "medium"), ("clearance", "medium"), ("sale", "medium"),
        ("unsubscribe", "medium"), ("subscribe", "medium"), ("deal", "medium"), ("offer", "medium"),
        ("re:\\d+\\s?%\\s?off", "medium"),
    ],
}

CATEGORY_LABELS = {
    "urgency": "Urgency language",
    "prize_money": "Prize / money content",
    "phishing": "Account / credential language",
    "promotional": "Promotional language",
    "url": "Links",
}

# Candidate URL pattern (shared with the browser). Matches explicit URLs, www. links,
# well-known shorteners and bare domains with common TLDs (not e-mail addresses).
URL_PATTERN = (
    r"(?:https?:\/\/|www\.)[^\s<>\"'\]\)]+"
    r"|\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|rebrand\.ly|cutt\.ly|shorturl\.at)\/[^\s<>\"'\]\)]*"
    r"|(?<![@\w.\-])[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)*\."
    r"(?:com|net|org|info|biz|xyz|top|click|link|online|site|club|win|tk|ml|ga|cf|gq|co|in|io|us|uk|ru|cn)"
    r"(?![a-z0-9\-])(?:\/[^\s<>\"'\]\)]*)?"
)
_URL_RE = re.compile(URL_PATTERN, re.I | re.A)
_TRAILING_PUNCT = re.compile(r"[.,;:!?]+$")


def _phrase_to_regex(entry: str) -> str:
    if entry.startswith("re:"):
        return entry[3:]
    pattern = re.escape(entry).replace(r"\ ", r"\s+").replace("'", "['’]").replace(r"\'", "['’]")
    # re.escape leaves "'" alone on py3.7+, but escape % (not escaped) is fine as-is.
    if re.match(r"\w", entry[0]):
        pattern = r"\b" + pattern
    if re.match(r"\w", entry[-1]):
        pattern += r"\b"
    return pattern


def lexicon_entries():
    """Flat list of {pattern, category, severity, label} in a stable order."""
    entries = []
    for category, items in LEXICON.items():
        for phrase, severity in items:
            label = phrase[3:] if phrase.startswith("re:") else phrase
            entries.append({"pattern": _phrase_to_regex(phrase), "category": category,
                            "severity": severity, "regex": phrase.startswith("re:")})
    return entries


_ENTRIES = lexicon_entries()
_COMPILED = [(re.compile(e["pattern"], re.I | re.A), e) for e in _ENTRIES]


def client_config():
    """Everything the browser needs to mirror the keyword/URL counting."""
    return {"lexicon": _ENTRIES, "urlPattern": URL_PATTERN, "categoryLabels": CATEGORY_LABELS}


# ----------------------------------------------------------------------------
# Keyword matching (leftmost-longest, non-overlapping) -- mirrored in static/js/core.js
# ----------------------------------------------------------------------------
def find_keyword_spans(text: str):
    candidates = []
    for regex, entry in _COMPILED:
        for m in regex.finditer(text):
            if m.end() > m.start():
                candidates.append((m.start(), m.end(), entry["category"], entry["severity"]))
    candidates.sort(key=lambda c: (c[0], -(c[1] - c[0])))
    spans, cursor = [], 0
    for start, end, category, severity in candidates:
        if start >= cursor:
            spans.append({"start": start, "end": end, "category": category, "severity": severity})
            cursor = end
    return spans


# ----------------------------------------------------------------------------
# URL analysis
# ----------------------------------------------------------------------------
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "rebrand.ly", "cutt.ly", "shorturl.at"}
SUSPICIOUS_TLDS = {"xyz", "top", "click", "link", "online", "site", "club", "win", "tk", "ml",
                   "ga", "cf", "gq", "ru", "cn", "work", "loan", "zip", "mov", "icu", "buzz"}
POPULAR_DOMAINS = {
    "google.com", "youtube.com", "microsoft.com", "apple.com", "amazon.com", "amazon.in",
    "github.com", "wikipedia.org", "linkedin.com", "facebook.com", "twitter.com", "x.com",
    "instagram.com", "paypal.com", "netflix.com", "stackoverflow.com", "python.org",
    "mozilla.org", "zoom.us", "slack.com", "dropbox.com", "outlook.com", "office.com",
    "live.com", "yahoo.com", "gmail.com", "adobe.com", "ebay.com", "flipkart.com",
}
BRANDS = {"paypal", "amazon", "apple", "microsoft", "google", "netflix", "facebook",
          "instagram", "whatsapp", "linkedin", "dropbox", "hdfcbank", "icicibank", "wellsfargo"}
SENSITIVE_WORDS = ("login", "signin", "verify", "secure", "account", "update", "confirm",
                   "bank", "wallet", "password", "billing")
_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu"}


def _registrable_domain(host: str) -> str:
    labels = host.split(".")
    if len(labels) >= 3 and labels[-2] in _SECOND_LEVEL and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def find_urls(text: str):
    urls = []
    for m in _URL_RE.finditer(text):
        raw = _TRAILING_PUNCT.sub("", m.group(0))
        if raw:
            urls.append((m.start(), m.start() + len(raw), raw))
    return urls


def analyze_url(raw: str) -> dict:
    has_scheme = bool(re.match(r"https?://", raw, re.I))
    parse_target = raw if has_scheme else "//" + raw
    try:
        parts = urlsplit(parse_target)
        host = (parts.hostname or "").lower()
    except ValueError:
        parts, host = None, ""

    flags, score = [], 0

    def flag(points, message):
        nonlocal score
        score += points
        flags.append(message)

    registrable = _registrable_domain(host) if host else ""
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    host_tokens = set(re.split(r"[.\-]", host))
    is_ip = bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host))

    if host in SHORTENERS:
        flag(40, "Link shortener hides the real destination")
    if is_ip:
        flag(50, "Uses a raw IP address instead of a domain name")
    if parts is not None and parts.username is not None:
        flag(40, "Contains '@' in the address (can disguise the real host)")
    if has_scheme and raw.lower().startswith("http://"):
        flag(15, "Not using HTTPS")
    if tld in SUSPICIOUS_TLDS:
        flag(25, f"Uncommon top-level domain (.{tld}) often seen in spam")
    if "xn--" in host:
        flag(35, "Internationalised (punycode) domain can imitate a real one")
    if not is_ip and host and len(host.split(".")) - len(registrable.split(".")) >= 3:
        flag(15, "Unusually many sub-domains")
    if host.count("-") >= 2:
        flag(15, "Many hyphens in the domain name")
    impersonated = sorted(b for b in BRANDS
                          if b in host_tokens and registrable.split(".")[0] != b)
    if impersonated:
        flag(45, f"Mentions '{impersonated[0]}' but is not the official {impersonated[0]} domain")
    path_part = (parts.path + "?" + parts.query).lower() if parts else ""
    if any(w in host or w in path_part for w in SENSITIVE_WORDS) and registrable not in POPULAR_DOMAINS:
        flag(15, "Contains account/login-style words")
    if len(raw) > 100:
        flag(10, "Very long address")

    score = min(score, 100)
    if registrable in POPULAR_DOMAINS and score < 25:
        label = "Safe-looking"
    elif score >= 25:
        label = "Suspicious"
    else:
        label = "Unknown"

    https = "yes" if raw.lower().startswith("https://") else ("no" if has_scheme else "unknown")
    return {"url": raw, "domain": host or raw, "https": https, "label": label, "score": score,
            "reasons": flags or (["Recognised, widely used domain"] if label == "Safe-looking"
                                 else ["No warning signs found, but the domain is not recognised"])}


# ----------------------------------------------------------------------------
# Statistics, indicators, breakdown
# ----------------------------------------------------------------------------
def compute_stats(text: str, keyword_spans, urls) -> dict:
    sentences = [s for s in re.split(r"[.!?]+(?:\s+|$)", text) if s.strip()]
    return {
        "characters": len(text),
        "words": len(re.findall(r"\S+", text)),
        "sentences": len(sentences),
        "urls": len(urls),
        "suspicious_keywords": len(keyword_spans),
        "capital_letters": sum(1 for c in text if c.isupper()),
        "special_characters": sum(1 for c in text if not c.isalnum() and not c.isspace()),
        "exclamation_marks": text.count("!"),
    }


def _caps_info(text: str):
    letters = [c for c in text if c.isalpha()]
    ratio = (sum(1 for c in letters if c.isupper()) / len(letters)) if letters else 0.0
    caps_words = [w for w in re.findall(r"\b[A-Z][A-Z0-9']{2,}\b", re.sub(_URL_RE, " ", text))]
    return len(letters), ratio, caps_words


def _formatting_info(text: str, stats: dict):
    repeated = re.findall(r"[!?]{2,}|\${2,}", text)
    special_ratio = stats["special_characters"] / max(stats["characters"], 1)
    return repeated, special_ratio


def build_indicators(text, spans, url_results, stats):
    """Only indicators that are actually detected are returned."""
    indicators = []
    by_cat = {}
    for s in spans:
        by_cat.setdefault(s["category"], []).append(text[s["start"]:s["end"]].lower())

    if spans:
        distinct = sorted(set(t for items in by_cat.values() for t in items))
        indicators.append({"id": "keywords", "title": "Suspicious keywords", "severity": "medium",
                           "detail": f"{len(spans)} suspicious keyword(s) found: " + ", ".join(distinct[:8])
                                     + ("…" if len(distinct) > 8 else "")})
    for cat, title, noun in (("urgency", "Urgency-based language", "urgency phrase(s)"),
                             ("prize_money", "Prize / money-related content", "prize or money term(s)"),
                             ("phishing", "Account / credential language", "account-related phrase(s)"),
                             ("promotional", "Promotional language", "promotional term(s)")):
        if cat in by_cat:
            severe = any(s["severity"] == "high" and s["category"] == cat for s in spans)
            indicators.append({"id": cat, "title": title, "severity": "high" if severe else "medium",
                               "detail": f"{len(by_cat[cat])} {noun}: " + ", ".join(sorted(set(by_cat[cat]))[:6])})

    flagged = [u for u in url_results if u["label"] == "Suspicious"]
    if flagged:
        indicators.append({"id": "urls", "title": "Suspicious URLs", "severity": "high",
                           "detail": f"{len(flagged)} of {len(url_results)} link(s) show warning signs: "
                                     + ", ".join(u["domain"] for u in flagged[:4])})

    n_letters, ratio, caps_words = _caps_info(text)
    if (n_letters >= 15 and ratio >= 0.30) or len(caps_words) >= 3:
        indicators.append({"id": "caps", "title": "Excessive capitalization", "severity": "medium",
                           "detail": f"{round(ratio * 100)}% of letters are uppercase"
                                     + (f"; ALL-CAPS words: {', '.join(caps_words[:5])}" if caps_words else "")})

    repeated, special_ratio = _formatting_info(text, stats)
    if stats["exclamation_marks"] >= 3 or repeated or special_ratio > 0.15:
        parts = []
        if stats["exclamation_marks"] >= 3:
            parts.append(f"{stats['exclamation_marks']} exclamation marks")
        if repeated:
            parts.append("repeated punctuation/symbols")
        if special_ratio > 0.15:
            parts.append(f"{round(special_ratio * 100)}% special characters")
        indicators.append({"id": "formatting", "title": "Unusual formatting", "severity": "medium",
                           "detail": ", ".join(parts).capitalize()})
    return indicators


def build_breakdown(text, spans, url_results, stats):
    """Heuristic risk factors, each 0-100. These are simple rules, not model outputs."""
    keyword_risk = min(100, sum(18 if s["severity"] == "high" else 8 for s in spans))
    url_risk = max((u["score"] for u in url_results), default=0)
    urgency_risk = min(100, sum(30 if s["severity"] == "high" else 20
                                for s in spans if s["category"] == "urgency"))
    n_letters, ratio, caps_words = _caps_info(text)
    repeated, special_ratio = _formatting_info(text, stats)
    formatting_risk = min(100, round(
        (min(ratio, 0.6) / 0.6 * 45 if n_letters >= 15 else 0)
        + min(stats["exclamation_marks"], 5) * 8
        + len(repeated) * 10
        + min(special_ratio, 0.3) / 0.3 * 15))
    return [
        {"id": "keywords", "label": "Keyword risk", "value": keyword_risk},
        {"id": "urls", "label": "URL risk", "value": url_risk, "applicable": bool(url_results)},
        {"id": "urgency", "label": "Urgency", "value": urgency_risk},
        {"id": "formatting", "label": "Formatting", "value": formatting_risk},
    ]


def heuristic_level(breakdown) -> str:
    peak = max(b["value"] for b in breakdown)
    return "high" if peak >= 70 else ("medium" if peak >= 35 else "low")


def analyze_text(text: str) -> dict:
    """Run every rule-based check and return a JSON-serialisable dict."""
    spans = find_keyword_spans(text)
    found_urls = find_urls(text)
    url_results = [analyze_url(raw) for _, _, raw in found_urls]
    stats = compute_stats(text, spans, found_urls)
    indicators = build_indicators(text, spans, url_results, stats)
    breakdown = build_breakdown(text, spans, url_results, stats)

    # Segments for highlighting: keyword spans + URL spans, keyword spans win on overlap.
    marks = [{"start": s["start"], "end": s["end"], "category": s["category"],
              "severity": "high" if s["severity"] == "high" else "medium"} for s in spans]
    for (start, end, _), result in zip(found_urls, url_results):
        if any(start < m["end"] and end > m["start"] for m in marks):
            continue
        severity = {"Suspicious": "high", "Unknown": None, "Safe-looking": "safe"}[result["label"]]
        if severity:
            marks.append({"start": start, "end": end, "category": "url", "severity": severity})
    marks.sort(key=lambda m: m["start"])
    segments, cursor = [], 0
    for m in marks:
        if m["start"] > cursor:
            segments.append({"text": text[cursor:m["start"]], "severity": None, "category": None})
        segments.append({"text": text[m["start"]:m["end"]], "severity": m["severity"], "category": m["category"]})
        cursor = m["end"]
    if cursor < len(text):
        segments.append({"text": text[cursor:], "severity": None, "category": None})

    keyword_counts = {}
    for s in spans:
        key = (text[s["start"]:s["end"]].lower(), s["category"], s["severity"])
        keyword_counts[key] = keyword_counts.get(key, 0) + 1
    keywords = [{"text": k[0], "category": k[1], "severity": k[2], "count": c}
                for k, c in sorted(keyword_counts.items(), key=lambda kv: (kv[0][2] != "high", -kv[1], kv[0][0]))]

    return {"stats": stats, "indicators": indicators, "breakdown": breakdown,
            "heuristic_level": heuristic_level(breakdown), "keywords": keywords,
            "urls": url_results, "segments": segments}


def recommendation(risk_level: str, model_prediction: str, heuristic_lvl: str, has_flagged_urls: bool) -> str:
    """Plain-language advice combining the model's risk band with the rule-based findings."""
    if risk_level == "high":
        advice = ("Treat this email as spam or phishing. Do not click links, open attachments, or reply. "
                  "Delete it or report it as spam.")
    elif risk_level == "suspicious":
        advice = ("The model is unsure about this email. Review it carefully before acting: "
                  "check the sender address and do not enter personal or payment details.")
    else:
        advice = "The model considers this email low risk. Normal caution still applies."
        if heuristic_lvl == "high" or has_flagged_urls:
            advice = ("The model considers this email low risk, but the rule-based checks found warning signs. "
                      "Verify the sender and links before clicking anything.")
    if risk_level != "high" and has_flagged_urls and "links" not in advice:
        advice += " Some links look suspicious; avoid opening them."
    return advice
