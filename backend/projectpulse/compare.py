"""Compare two stored audits, only claiming deltas that are actually comparable."""
def compare_audits(a, b):
    """a = earlier, b = later (dicts from Store.get_audit)."""
    notes, ca = [], {c["category"]: c for c in a["categories"]}
    cb = {c["category"]: c for c in b["categories"]}
    compatible = a["scoring_version"] == b["scoring_version"]
    if not compatible:
        notes.append(f'Scoring engine changed ({a["scoring_version"]} -> {b["scoring_version"]}); score differences may not reflect real changes.')
    cats = {}
    for name in sorted(set(ca) | set(cb)):
        sa, sb = ca.get(name, {}).get("score"), cb.get(name, {}).get("score")
        if sa is not None and sb is not None:
            cats[name] = {"before": sa, "after": sb, "delta": round(sb - sa, 2)}
        elif sa != sb:
            cats[name] = {"before": sa, "after": sb, "delta": None}
            notes.append(f"{name}: evidence availability changed, so no point difference is reported.")
    if a["effective_weights"] != b["effective_weights"]:
        notes.append("Effective category weights differ between audits because different categories were evaluated.")
    delta = round(b["overall"] - a["overall"], 2) if a["overall"] is not None and b["overall"] is not None else None
    fa = {f["key"] for f in a["findings"]}; fb = {f["key"] for f in b["findings"]}
    return {"overall": {"before": a["overall"], "after": b["overall"], "delta": delta, "comparable": compatible},
            "categories": cats, "findings": {"resolved": sorted(fa - fb), "new": sorted(fb - fa), "remaining": sorted(fa & fb)},
            "notes": notes}
