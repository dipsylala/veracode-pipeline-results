# veracode-pipeline-results

A reusable agent skill + scripts pattern for interpreting [Veracode pipeline scan](https://docs.veracode.com/r/pipeline_scan) JSON results. It summarises findings by severity, file, and issue type, and provides prioritised remediation guidance.

Works with GitHub Copilot, Cursor, Claude Code, and any agent that supports the `SKILL.md` convention.

## What it does

- Parses the JSON output from a Veracode pipeline scan (`filtered_results*.json`)
- Reports a **scan overview**: status, modules scanned, and total finding count
- Breaks down findings by **severity** and **issue type**
- Groups findings **by source file** with severity-sorted rows
- Supports both a default **Summary** mode and an on-request **Detail** mode for drilling into a specific finding, including taint data-path analysis and false-positive assessment

## Usage

### GitHub Copilot, Cursor, and other AI IDEs

Copy or clone this folder into your project (or home directory for personal use):

| Location | Scope |
| ---------- | ------- |
| `.github/skills/veracode-pipeline-results/` | Project — GitHub Copilot |
| `.agents/skills/veracode-pipeline-results/` | Project — other agents |
| `.claude/skills/veracode-pipeline-results/` | Project — Claude/Cursor |

The agent will automatically load the skill when relevant, or you can invoke it directly:

> "Summarise this Veracode scan: `/path/to/filtered_results.json`"

> "Give me details on finding 12 in `filtered_results.json`"

## Repository contents

| Path | Description |
|------|-------------|
| `SKILL.md` | Skill definition and agent instructions |
| `REFERENCE.md` | Full JSON schema reference for Veracode pipeline scan output |
| `scripts/pipeline_summary.py` | Extracts scan overview, severity breakdown, issue-type breakdown, and findings grouped by file |
| `scripts/pipeline_detail.py` | Extracts full detail for a single finding, including taint data path |

## Scripts

The scripts under `scripts/` can also be run directly against a scan file:

```bash
# Full scan summary
python scripts/pipeline_summary.py path/to/filtered_results.json

# Detail for a specific finding by issue ID
python scripts/pipeline_detail.py path/to/filtered_results.json <issue_id>
```

**Requirements:** Python 3.6+, no third-party dependencies.

## Remediation priority

1. **Very High** — fix immediately; likely exploitable
2. **High** — fix in current sprint; exploitability is neutral or likely
3. **Medium / Low** — schedule for remediation; lower exploitability risk
