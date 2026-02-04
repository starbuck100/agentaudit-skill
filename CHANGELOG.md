# Changelog — AgentAudit Skill

> Detaillierte Historie aller Änderungen. Neueste zuerst.

---

## 2026-02-04 10:54

### Exit Code 3 "Audit Gap" Warning

- **Was:** Exit Code 3 (UNKNOWN) löst jetzt explizite Warnung aus statt stilles Durchwinken
- **Warum:** "Unknown ≠ Safe" — Agents behandelten fehlende Audit-Daten als grünes Licht
- **Files:**
  - `SKILL.md` — Neue Sektion "Exit Code 3 — The Audit Gap", 4 Red-Flag Checks, User-Bestätigung erforderlich
  - `scripts/gate.sh` — Enhanced JSON Output mit `warning` und `required_checks` Array
- **Commit:** `e9258ea`
- **Breaking:** Nein

---

## 2026-02-03 01:03

### Initial Structure

- **Was:** Skill-Repo erstellt mit vollständiger SKILL.md v2
- **Warum:** Separates Repo für einfachere Installation via `clawhub install` oder `git clone`
- **Files:**
  - `SKILL.md` — Hauptdokumentation mit Gate-Flow, API-Reference, Pattern-IDs
  - `scripts/gate.sh` — Security Gate Script
  - `scripts/upload.sh` — Report Upload Script
  - `scripts/register.sh` — Agent Registration Script
  - `scripts/verify.sh` — Integrity Verification Script
  - `prompts/audit-prompt.md` — Audit Instructions
  - `prompts/review-prompt.md` — Peer Review Instructions
- **Commit:** Initial
- **Breaking:** N/A

---

<!-- 
TEMPLATE für neue Einträge:

## YYYY-MM-DD HH:mm

### {Feature/Fix Name}

- **Was:** 
- **Warum:** 
- **Files:**
  - `path/to/file`
- **Commit:** ``
- **Breaking:** Nein

-->
