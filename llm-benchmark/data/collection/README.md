# Seed Data Collection

This directory contains scripts to collect **real tool outputs** for use as seed samples in the benchmark.

## Collection Methods

| Category | Method | Script/Tool |
|----------|--------|-------------|
| `github_issue` | GitHub API | `collect_github.py` |
| `email` | Gemini MCP | Manual extraction |
| `calendar` | Gemini MCP | Manual extraction |
| `cloud_drive` | Gemini MCP | Manual extraction |
| `reference_json` | Manual | Synthetic data |
| `web_dom` | Manual | Synthetic (mimics Nanobrowser/Atlas formats) |

## Available Scripts

### `collect_github.py`

Collects GitHub issues with automatic anonymization.

```bash
# Basic collection (no auth required)
python data/collection/collect_github.py --repo pytorch/pytorch --limit 10

# With comments (recommended)
python data/collection/collect_github.py --repo microsoft/vscode --limit 10 --with-comments

# Higher rate limits with token
export GITHUB_TOKEN="your_token_here"
python data/collection/collect_github.py --repo django/django --limit 20 --with-comments
```

### `anonymizer.py`

Utility module for anonymizing personal data (usernames, emails, URLs).

## Google Services via Gemini MCP

For Gmail, Calendar, and Drive data, use the **Gemini Workspace MCP extension**:

1. Use Gemini CLI with workspace tools
2. Extract raw JSON responses from `~/.gemini/` chat history
3. Save to appropriate `data/seeds/{category}/` directories

See `QUICKSTART.md` for detailed instructions.

## Storage Structure

```
data/seeds/
├── calendar/          # Calendar events (JSON)
├── cloud_drive/       # Drive file metadata (JSON)
├── email/             # Email messages (JSON)
├── github_issue/      # GitHub issues (JSON)
├── reference_json/    # Synthetic test data (JSON)
└── web_dom/           # Synthetic DOM data mimicking web agent formats (TXT)
```

## Guidelines

- **Quality over quantity**: 5-10 diverse seeds per category
- **Anonymization**: Always remove sensitive data
- **Variety**: Different schemas, sizes, and edge cases
