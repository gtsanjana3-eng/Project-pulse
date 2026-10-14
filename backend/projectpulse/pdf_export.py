import io
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from xml.sax.saxutils import escape as esc
from .presentation import CATEGORY_LABEL

def _tbl(rows, widths):
    t = Table(rows, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), .25, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")])]))
    return t

def build_pdf(project, audit, report):
    buf, st = io.BytesIO(), getSampleStyleSheet()
    P = lambda s, style="BodyText": Paragraph(esc(str(s)), st[style])
    cell = lambda s: Paragraph(esc(str(s)), st["BodyText"])
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18*mm, rightMargin=18*mm, topMargin=16*mm, bottomMargin=16*mm,
                            title=f"ProjectPulse report - {project['name']}", author="ProjectPulse AI")
    o = audit["overall"]
    el = [P(f"ProjectPulse AI audit report: {project['name']}", "Title"),
          P(f"Target: {project['url']}   |   Attempt {audit['attempt_no']}   |   {audit['created_at']}   |   Scoring engine v{audit['scoring_version']}"),
          Spacer(1, 6), P("Overall score", "Heading2"),
          P(f"{o:.2f} / 100" if o is not None else "Insufficient evidence - no overall score"),
          P("Weights used: " + (", ".join(f"{CATEGORY_LABEL.get(k, k)} {v*100:.0f}%" for k, v in audit["effective_weights"].items()) or "none") + ". Categories without enough evidence are excluded and weights re-normalised."),
          Spacer(1, 6), P("Category scores", "Heading2")]
    rows = [["Category", "Score", "Status", "Checks run", "Confidence"]]
    for c in audit["categories"]:
        rows.append([CATEGORY_LABEL.get(c["category"], c["category"]), "-" if c["score"] is None else f"{c['score']:.1f}",
                     c["status"].replace("_", " "), c["checks_run"], c["confidence"]])
    el += [_tbl(rows, [45*mm, 22*mm, 48*mm, 25*mm, 30*mm]), Spacer(1, 8), P("Checks executed", "Heading2")]
    rows = [["Check", "Category", "Status", "Evidence"]] + [[cell(c["name"]), c.get("category", ""), c["status"], cell(c["evidence"])] for c in report.get("checks", [])]
    el += [_tbl(rows, [55*mm, 28*mm, 20*mm, 67*mm]), Spacer(1, 8), P("Findings", "Heading2")]
    if audit["findings"]:
        rows = [["Severity", "Finding", "Evidence", "Recommended fix", "Status"]] + [[f["severity"], cell(f["title"]), cell(f["evidence"]), cell(f["recommended_fix"]), f["status"]] for f in audit["findings"]]
        el.append(_tbl(rows, [18*mm, 38*mm, 30*mm, 64*mm, 20*mm]))
    else: el.append(P("No findings in the checks that were run."))
    el += [Spacer(1, 8), P("Limitations", "Heading2"), P(report.get("limitations", "")),
           P("A high score does not mean the application is secure or error-free.")]
    doc.build(el); return buf.getvalue()
