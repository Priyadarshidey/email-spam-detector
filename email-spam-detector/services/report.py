"""Generate the downloadable PDF security report (ReportLab)."""
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

VERDICT = {"high": ("SPAM DETECTED", "#dc2626"),
           "suspicious": ("SUSPICIOUS - REVIEW CAREFULLY", "#d97706"),
           "safe": ("EMAIL APPEARS SAFE", "#16a34a")}
INK, MUTED, LINE = colors.HexColor("#0f172a"), colors.HexColor("#64748b"), colors.HexColor("#e2e8f0")


def _p(text, style):
    return Paragraph(escape(str(text)), style)


def build_report_pdf(analysis: dict, email_text: str) -> bytes:
    model, rules = analysis["model"], analysis["rules"]
    title, accent = VERDICT[model["risk_level"]]
    base = getSampleStyleSheet()["Normal"]
    body = ParagraphStyle("body", parent=base, fontName="Helvetica", fontSize=9.5, leading=14, textColor=INK)
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=11, textColor=MUTED)
    h2 = ParagraphStyle("h2", parent=body, fontName="Helvetica-Bold", fontSize=12, spaceBefore=14, spaceAfter=6)
    h1 = ParagraphStyle("h1", parent=body, fontName="Helvetica-Bold", fontSize=20, leading=24)
    verdict = ParagraphStyle("verdict", parent=body, fontName="Helvetica-Bold", fontSize=15,
                             textColor=colors.HexColor(accent))
    cell = ParagraphStyle("cell", parent=body, fontSize=8.5, leading=11)

    def table(rows, widths, header=True):
        t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
        style = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
                 ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]
        if header:
            style += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9"))]
        t.setStyle(TableStyle(style))
        return t

    story = [_p("Email Security Analysis Report", h1),
             _p(f"Generated {analysis['analyzed_at_display']}", small), Spacer(1, 10),
             _p(title, verdict), Spacer(1, 6)]

    story.append(table([
        [_p("Model prediction", cell), _p("Spam" if model["prediction"] == "spam" else "Not spam", cell)],
        [_p("Spam probability", cell), _p(f"{model['spam_probability']}%", cell)],
        [_p("Not-spam probability", cell), _p(f"{model['not_spam_probability']}%", cell)],
        [_p("Model confidence", cell), _p(f"{model['confidence_label']} ({model['confidence']}%)", cell)],
        [_p("Risk score", cell), _p(f"{model['risk_score']}/100 ({model['risk_level'].replace('high', 'high risk')})", cell)],
        [_p("Model used", cell), _p(model["algorithm"], cell)],
        [_p("Analysis date/time", cell), _p(analysis["analyzed_at_display"], cell)],
    ], [50 * mm, 120 * mm], header=False))

    story += [_p("Security recommendation", h2), _p(analysis["recommendation"], body)]

    story.append(_p("Detected indicators (rule-based)", h2))
    if rules["indicators"]:
        story.append(table([[_p("Indicator", cell), _p("Details", cell)]] +
                           [[_p(i["title"], cell), _p(i["detail"], cell)] for i in rules["indicators"]],
                           [50 * mm, 120 * mm]))
    else:
        story.append(_p("No rule-based warning indicators were detected.", body))

    story.append(_p("Suspicious keywords", h2))
    if rules["keywords"]:
        story.append(table([[_p("Keyword", cell), _p("Category", cell), _p("Level", cell), _p("Count", cell)]] +
                           [[_p(k["text"], cell), _p(k["category"].replace("_", "/"), cell),
                             _p("High risk" if k["severity"] == "high" else "Suspicious", cell), _p(k["count"], cell)]
                            for k in rules["keywords"][:25]], [70 * mm, 45 * mm, 35 * mm, 20 * mm]))
    else:
        story.append(_p("None detected.", body))

    story.append(_p("URLs detected", h2))
    if rules["urls"]:
        story.append(table([[_p("URL", cell), _p("Domain", cell), _p("HTTPS", cell), _p("Assessment", cell)]] +
                           [[_p(u["url"][:70], cell), _p(u["domain"], cell), _p(u["https"], cell), _p(u["label"], cell)]
                            for u in rules["urls"][:20]], [70 * mm, 45 * mm, 20 * mm, 35 * mm]))
        story.append(_p("URL assessments are rule-based and unverified: no link was visited or checked "
                        "against a blocklist.", small))
    else:
        story.append(_p("No URLs found.", body))

    story.append(_p("Rule-based risk factors", h2))
    story.append(table([[_p("Factor", cell), _p("Score", cell)]] +
                       [[_p(b["label"], cell), _p(f"{b['value']}%" if b.get("applicable", True) else "n/a", cell)]
                        for b in rules["breakdown"]], [100 * mm, 70 * mm]))

    excerpt = email_text[:600] + ("…" if len(email_text) > 600 else "")
    story += [_p("Analysed email (excerpt)", h2), _p(excerpt, small), Spacer(1, 14),
              _p("The model prediction and risk score come from the trained Naive Bayes classifier. "
                 "Indicators, keywords, URL assessments and risk factors are rule-based heuristics shown to "
                 "help explain the result. This tool provides automated analysis for educational and "
                 "informational purposes. It should not be considered a definitive security verdict.", small)]

    buffer = BytesIO()
    SimpleDocTemplate(buffer, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm, topMargin=18 * mm,
                      bottomMargin=18 * mm, title="Email Security Analysis Report").build(story)
    return buffer.getvalue()
