"""Deterministic presentation generator grounded in project inputs + stored audit evidence.
Anything the user did not supply or the audit did not measure becomes a [CONFIRM: ...] placeholder.
(An LLM can later polish wording via the optional `polish` hook; it never supplies facts.)"""
WPM = 130
SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SHARE = {"opening": .08, "problem": .15, "solution": .15, "features": .20, "technical": .15, "demo": .10, "results": .12, "conclusion": .05}
CATEGORY_LABEL = {"code_quality": "Code quality", "security": "Security", "performance": "Performance", "testing": "Testing",
                  "accessibility": "Accessibility", "functionality": "Functionality", "problem_alignment": "Problem alignment"}

def _label(c): return CATEGORY_LABEL.get(c, c)

def _facts(project, audit, report):
    cats = {c["category"]: c for c in audit["categories"]}
    scored = {k: c for k, c in cats.items() if c["score"] is not None}
    checks = report.get("checks", [])
    run = [c for c in checks if c["status"] in ("passed", "failed")]
    open_f = sorted([f for f in audit["findings"] if f["status"] != "accepted_risk"], key=lambda f: SEV_ORDER.index(f["severity"]))
    reachable = any(c["name"] == "Site reachable" and c["status"] == "passed" for c in checks)
    return dict(cats=cats, scored=scored, not_eval=sorted(k for k, c in cats.items() if c["score"] is None), checks_run=len(run),
                open_findings=open_f, reachable=reachable, overall=audit["overall"])

def _sent_pool(project, audit, f):
    name, url = project["name"], project["url"]
    needs = []
    def need(label): needs.append(label); return f"[CONFIRM: {label}]"
    problem = project.get("problem_statement") or need("add your problem statement")
    users = project.get("target_users"); users_s = f"It is built for {users}." if users else need("add your target users")
    desc = project.get("description") or need("add a one-line project description")
    feats, stack = project.get("features") or [], project.get("tech_stack") or []
    pool = {
     "opening": [f"Hello everyone, we are presenting {name}.", f"{name} is deployed at {url}."],
     "problem": [problem, users_s],
     "solution": [desc],
     "features": ([f"A feature we built: {x}." for x in feats] or [need("list your main features")])
                 + ["These features are described by the team; the automated audit did not independently verify them."],
     "technical": ([f"The team reports using {', '.join(stack)}; this was not verified by the audit."] if stack else [need("list your technology stack")])
                  + [f"The automated audit ran {f['checks_run']} checks against the live site, covering availability, HTTPS and security headers."]
                  + [f"{_label(k)} scored {c['score']:.1f} out of 100." for k, c in f["scored"].items()],
     "demo": [f"For the demo we open {url} first."] + [f"Then we show: {x}." for x in feats]
             + ["If the site is down, we switch to our recorded walkthrough."],
     "results": [(f"The audit gave an overall score of {f['overall']:.1f} out of 100, calculated only from the categories that could be evaluated."
                  if f["overall"] is not None else "The audit could not produce an overall score because there was not enough evidence.")]
               + [f"The audit found {len(f['open_findings'])} open issue(s); the most serious is: {f['open_findings'][0]['title']}." if f["open_findings"] else "The audit found no open issues in the checks that were run."]
               + [f"Not evaluated: {', '.join(_label(k) for k in f['not_eval'])}." if f["not_eval"] else ""]
               + ["A live-URL audit cannot see source code, backend logic or test coverage, so a good score is not proof of security or correctness."],
     "conclusion": [f"To summarise, {name} " + (f"addresses this problem for {users}." if users else "addresses this problem.")]
                   + [f"Our next step is to fix: {f['open_findings'][0]['recommended_fix']}" if f["open_findings"] else "Our next step is to expand testing with source-code analysis."]
                   + ["Thank you. We are happy to take questions."],
    }
    pool = {k: [s for s in v if s] for k, v in pool.items()}
    return pool, needs

def _script(pool, minutes):
    budget, text, words = minutes * WPM, [], 0
    for sec, share in SHARE.items():
        quota, used, lines = budget * share, 0, []
        for s in pool[sec]:
            n = len(s.split())
            if lines and used + n > quota: break          # always keep first sentence of a section
            lines.append(s); used += n
        text.append({"section": sec, "text": " ".join(lines)}); words += used
    return {"minutes": minutes, "words": words, "estimated_minutes": round(words / WPM, 1), "sections": text}

def _slides(project, audit, f, technical):
    n, url = project["name"], project["url"]
    sl = [("Title", [n, project.get("description") or "[CONFIRM: add description]"], "Logo or landing-page screenshot"),
          ("Problem", [project.get("problem_statement") or "[CONFIRM: add problem statement]", f"Users: {project.get('target_users') or '[CONFIRM]'}"], "One real-world photo or statistic you can cite"),
          ("Solution & features", [*(project.get("features") or ["[CONFIRM: list features]"])], "Screenshot of main workflow"),
          ("Live demo", [f"Open {url}", "Walk through the features in order"], "Live site"),
          ("Audit results", [f"Overall: {f['overall']:.1f}/100" if f["overall"] is not None else "Overall: insufficient evidence"]
              + [f"{_label(k)}: {c['score']:.1f}" for k, c in f["scored"].items()]
              + [f"Not evaluated: {', '.join(_label(k) for k in f['not_eval'])}"] * bool(f["not_eval"]), "Score bars from the dashboard"),
          ("Limitations & next steps", [x["title"] for x in f["open_findings"][:3]] or ["Expand tests with source-code analysis"], "Findings table")]
    if technical:
        sl[3:3] = [("Technology stack", [*(project.get("tech_stack") or ["[CONFIRM: list stack]"]), "Declared by the team; not verified by the audit"], "Stack logo grid"),
                   ("Architecture", ["[CONFIRM: no architecture evidence yet; connect the repository for a verified diagram]"], "Architecture diagram (only after verification)"),
                   ("Security & testing", [f"{f['checks_run']} automated checks run", *[f"{x['title']} ({x['severity']})" for x in f["open_findings"][:4]]], "Findings screenshot")]
    return [{"title": t, "bullets": b, "visual": v, "speaker_notes": f"Explain: {t}. Stay within what was verified."} for t, b, v in sl]

def _qa(project, audit, f):
    cats, name = f["cats"], project["name"]
    def st(k): c = cats.get(k); return f"{c['score']:.1f}/100 from {c['checks_run']} checks" if c and c["score"] is not None else "not evaluated"
    top = f["open_findings"]
    def a(text, confirm=None): return {"answer": text, "needs_confirmation": confirm or [], "grounded": not confirm}
    q = [("Problem selection", "Why did you choose this problem?", a(project.get("problem_statement") or "", None) if project.get("problem_statement") else a("", ["Why this problem matters to you and who is affected"])),
     ("Innovation", "What is new compared with existing solutions?", a("", ["Name two existing alternatives and what yours does differently"])),
     ("Technical architecture", "How is the system built?", a(f"The team reports: {', '.join(project['tech_stack'])}. The audit did not verify this.", ["Confirm the stack and data flow"]) if project.get("tech_stack") else a("", ["Describe frontend, backend, database and data flow"])),
     ("AI usage", "Where do you use AI and why?", a("", ["Whether AI is used, which model/service, and what it does"])),
     ("Database and APIs", "What database and external APIs do you rely on?", a("", ["Database choice and external APIs; the live audit cannot observe them"])),
     ("Security", "How secure is it?", a(f"The live audit security result is {st('security')}. " + (f"Open issues: {', '.join(x['title'] for x in top if x['category']=='security') or 'none found in the checks run'}. " ) + "This covers HTTPS and response headers only, not application logic.")),
     ("Testing", "How did you test it?", a(f"The automated audit ran {f['checks_run']} checks (functionality: {st('functionality')}). Testing category: {st('testing')}. We have not run project-specific tests unless you add them.", None if cats.get("testing", {}).get("score") is not None else ["Describe any tests you wrote or ran manually"])),
     ("Scalability", "Will it scale?", a("No load or scalability testing has been performed.", ["Hosting plan limits and any load testing you did"])),
     ("Limitations", "What are the limitations?", a("; ".join([f"{_label(k)} was not evaluated" for k in f["not_eval"]] + [x["title"] for x in top[:3]]) or "No limitations were detected by the checks run, but the audit cannot see source code or backend logic.")),
     ("Real-world usefulness", "Who would use this and why?", a(f"Intended users: {project['target_users']}." if project.get("target_users") else "", None if project.get("target_users") else ["Target users and evidence of need (do not claim usage numbers you do not have)"])),
     ("Future development", "What would you do next?", a("Next steps from the audit: " + ("; ".join(x["recommended_fix"] for x in top[:3]) if top else "add source-code analysis and project tests.")))]
    return [{"topic": t, "question": qu, **an} for t, qu, an in q]

def build_presentation(project, audit, report, polish=None):
    f = _facts(project, audit, report)
    pool, needs = _sent_pool(project, audit, f)
    feats = [{"feature": x, "status": "unverified", "note": "Declared by you; the quick audit cannot confirm it. Demonstrate it live."} for x in project.get("features") or []]
    verified = [{"item": "Deployed site is reachable", "evidence": "HTTP check"}] if f["reachable"] else []
    out = {
      "project": {"name": project["name"], "url": project["url"], "audit_id": audit["id"], "attempt_no": audit["attempt_no"], "scoring_version": audit["scoring_version"]},
      "introduction": {"title": project["name"], "problem": project.get("problem_statement"), "target_users": project.get("target_users"), "solution": project.get("description")},
      "features": {"declared": feats, "verified_by_audit": verified},
      "technology": {"declared_by_team_unverified": project.get("tech_stack") or [], "verified": [], "note": "Stack detection requires source code; none was analysed."},
      "architecture": {"status": "insufficient_evidence", "diagram": None, "note": "No repository evidence; no diagram generated to avoid inventing components."},
      "scripts": {f"{w}_minute": _script(pool, m) for m, w in ((3, "three"), (5, "five"), (10, "ten"))},
      "slides": {"concise": _slides(project, audit, f, False), "technical": _slides(project, audit, f, True)},
      "judge_qa": _qa(project, audit, f),
      "demo_plan": {"order": [f"Open {project['url']}"] + [f"Show: {x}" for x in project.get("features") or ["[CONFIRM: list features to demo]"]] + ["Show the audit dashboard and open findings"],
                    "emphasize": ["What was measured vs. what is only claimed", "How the score was calculated and what was not evaluated"],
                    "backup_plan": "Keep a screen recording and screenshots of each demo step; if the site is down, narrate from them and say so."},
      "needs_confirmation": sorted(set(needs)),
    }
    return polish(out) if polish else out
