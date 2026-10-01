# Quick Start Guide - Seed Collection

This guide explains how to collect seed samples for the benchmark.

## Overview

| Category | Collection Method | Seeds Location |
|----------|------------------|----------------|
| `github_issue` | `collect_github.py` script | `data/seeds/github_issue/` |
| `email` | Gemini MCP | `data/seeds/email/` |
| `calendar` | Gemini MCP | `data/seeds/calendar/` |
| `cloud_drive` | Gemini MCP | `data/seeds/cloud_drive/` |
| `reference_json` | Manual/synthetic | `data/seeds/reference_json/` |
| `web_dom` | Manual | `data/seeds/web_dom/` |

---

## GitHub Issues (Recommended - No API Keys Required)

The `collect_github.py` script collects GitHub issues with automatic anonymization.

```bash
# Basic collection (60 requests/hour limit without token)
python data/collection/collect_github.py --repo pytorch/pytorch --limit 15
python data/collection/collect_github.py --repo microsoft/vscode --limit 15

# With comments (recommended for richer data)
python data/collection/collect_github.py --repo django/django --limit 10 --with-comments

# Optional: Set GitHub token for higher rate limits (5000 req/hour)
export GITHUB_TOKEN="your_token_here"
python data/collection/collect_github.py --repo tensorflow/tensorflow --limit 20 --with-comments
```

**Features:**
- Automatic anonymization (usernames, emails, URLs)
- Collects issues and comments
- No API key required (optional for higher limits)

---

## Google Services (Gemini MCP)

For Gmail, Calendar, and Drive data, use the **Gemini Workspace MCP extension**.

### Setup

1. Install Gemini CLI with workspace extension
2. Authenticate with your Google account
3. Use MCP tool calls to retrieve data

### Collection via Gemini MCP

```bash
# Start Gemini CLI
gemini

# In Gemini, call the workspace tools:
# - get_email: Retrieve emails
# - list_events: Retrieve calendar events
# - search_drive: Search Drive files
```

### Extracting Raw Responses

The raw tool responses are stored in `~/.gemini/` chat history. Extract the JSON responses and save them to the appropriate seed directories:

```bash
# Email seeds
data/seeds/email/get-email-1.json
data/seeds/email/get-email-2.json

# Calendar seeds
data/seeds/calendar/list-events.json
data/seeds/calendar/list-calendars.json

# Drive seeds
data/seeds/cloud_drive/drive-search.json
```

### Expected JSON Formats

**Email** (`get-email-*.json`):
```json
{
  "id": "...",
  "threadId": "...",
  "labelIds": ["INBOX"],
  "snippet": "...",
  "subject": "...",
  "from": "Name <email@example.com>",
  "to": "...",
  "date": "...",
  "body": "...",
  "attachments": []
}
```

**Calendar** (`list-events.json`):
```json
[
  {
    "id": "...",
    "status": "confirmed",
    "htmlLink": "...",
    "summary": "Event Title",
    "start": {"dateTime": "2026-01-18T10:00:00+09:00", "timeZone": "Asia/Seoul"},
    "end": {"dateTime": "2026-01-18T11:00:00+09:00", "timeZone": "Asia/Seoul"}
  }
]
```

**Drive** (`drive-search.json`):
```json
{
  "files": [
    {
      "id": "...",
      "name": "filename.pdf",
      "mimeType": "application/pdf",
      "modifiedTime": "...",
      "viewedByMeTime": "..."
    }
  ]
}
```

---

## Manual Seeds

### reference_json

Synthetic JSON structures for testing. Create files in `data/seeds/reference_json/`.

### web_dom

Web DOM accessibility tree representations. Create `.txt` files in `data/seeds/web_dom/`.

---

## Verifying Seeds

```bash
# Check seed counts
echo "GitHub issues: $(ls -1 data/seeds/github_issue/*.json 2>/dev/null | wc -l)"
echo "Email: $(ls -1 data/seeds/email/*.json 2>/dev/null | wc -l)"
echo "Calendar: $(ls -1 data/seeds/calendar/*.json 2>/dev/null | wc -l)"
echo "Cloud Drive: $(ls -1 data/seeds/cloud_drive/*.json 2>/dev/null | wc -l)"
echo "Reference JSON: $(ls -1 data/seeds/reference_json/*.json 2>/dev/null | wc -l)"
echo "Web DOM: $(ls -1 data/seeds/web_dom/*.txt 2>/dev/null | wc -l)"

# Validate JSON
for file in data/seeds/email/*.json; do
    python -m json.tool "$file" > /dev/null && echo "$file: Valid" || echo "$file: Invalid"
done
```

---

## Available Scripts

| Script | Description |
|--------|-------------|
| `collect_github.py` | Collect GitHub issues with anonymization |
| `anonymizer.py` | Utility for anonymizing personal data |

---

## Tips

- **Quality over Quantity**: 5-10 diverse seeds per category is sufficient
- **Anonymization**: Always review collected seeds before committing
- **Variety**: Collect from different sources for better coverage
