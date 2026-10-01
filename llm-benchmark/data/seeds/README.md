# Seed Data Structure

This directory contains **seed samples** - real tool outputs collected from various sources. Seeds serve as templates for generating benchmark instances.

## Directory Organization

```
data/seeds/
├── calendar/          # Google Calendar events (JSON)
├── cloud_drive/       # Google Drive file metadata (JSON)
├── email/             # Email messages (JSON)
├── github_issue/      # GitHub issues and comments (JSON)
├── reference_json/    # Domain-agnostic structured snapshots (JSON)
├── slack/             # Slack messages (JSON)
├── web_html/          # Web pages (HTML)
└── web_search/        # Search results (JSON)
```

## File Structure

### Separated by API Endpoint

Each seed collection stores data from different API endpoints in separate files:

**Example: GitHub Issues**
```
github_issue/
├── api_001_issue_bug_report.json          # Issue data
├── api_001_comments_bug_report.json       # Comments for issue #001
├── api_002_issue_feature_request.json     # Issue data
├── api_002_comments_feature_request.json  # Comments for issue #002
└── api_manifest.json                      # Mapping of files to endpoints
```

### Manifest File Format

Each collection includes a manifest (`{prefix}_manifest.json`) that maps files to their source API endpoints:

```json
{
  "repository": "pytorch/pytorch",
  "collection_info": {
    "collected_at": "2026-01-10T00:46:38Z",
    "total_issues": 10,
    "anonymized": true
  },
  "files": [
    {
      "index": 1,
      "issue_number": 172059,
      "issue_file": "api_001_issue_bug_report.json",
      "issue_endpoint": "GET /repos/pytorch/pytorch/issues",
      "issue_url": "https://api.github.com/repos/pytorch/pytorch/issues/172059",
      "comments_file": "api_001_comments_bug_report.json",
      "comments_endpoint": "GET /repos/pytorch/pytorch/issues/172059/comments",
      "comments_url": "https://api.github.com/repos/pytorch/pytorch/issues/172059/comments",
      "comments_count": 3
    }
  ]
}
```

### Benefits of This Structure

1. **Clear data provenance** - Know exactly which API endpoint each file came from
2. **Reusable components** - Comments can be used separately or combined with issues
3. **Format flexibility** - Different endpoints may have different schemas
4. **Easy validation** - Validate each endpoint's data independently
5. **Transparent benchmarking** - Clear mapping for reproducibility

### Reference JSON Schema (reference_json/)

Academic-paper themed snapshots, self-contained (no manifests):
- **paper_id**: `cycle1-{number}`
- **title**, **status** (submitted/under_review/revisions_requested)
- **abstract**: short text
- **metadata**: security conference, track, sub_tracks, avg_score, optional decision/timestamps
- **reviews**: 4 reviews `{reviewer, score, summary, comments}`

Complexity tiers:
- `cycle1_001_minimal.json`: core fields only (paper_id, title, status, track, avg_score).
- `cycle1_002_basic.json`: adds authors/abstract/keywords, year, and 4 reviews.
- `cycle1_003_complex.json`: adds decision/timestamps and denser reviews.



## File Naming Convention

```
{prefix}_{index}_{type}_{description}.{ext}

Components:
- prefix: Collection identifier (e.g., "api", "manual")
- index: Sequential number (001, 002, ...)
- type: Data type ("issue", "comments", etc.)
- description: Slug from title/content (max 30 chars)
- ext: File extension (json, html)

Examples:
- api_001_issue_bug_report.json
- api_001_comments_bug_report.json
- manual_005_issue_feature_request.json
- ref_001_snapshot.json (full synthetic snapshot with envelope/summary/entries/checks)
- ref_entries_001.json (entries-focused cut of snapshot 001)
```

## Anonymization

All seeds are automatically anonymized before storage:

- **Usernames** → Fake names (e.g., "alice_s", "bob_j")
- **Emails** → Fake emails (e.g., "alice.smith@example.com")
- **URLs** → Sanitized URLs (e.g., "https://example.com/repo/...")
- **API tokens** → Removed completely

Anonymization is:
- **Consistent** - Same input always maps to same fake output
- **Realistic** - Uses real-looking names and emails
- **Structure-preserving** - Maintains all fields and data types

## Usage in Benchmark

1. **Parser Development** (Phase 2)
   - Use seeds to develop format parsers
   - Test transformation from JSON → Markdown/CSV/Text

2. **Attack Injection** (Phase 4)
   - Seeds provide base structure
   - Attacks inject adversarial data into specific fields

3. **Evaluation** (Phase 6)
   - Compare LLM outputs against groundtruth from seeds
   - Test robustness with clean vs attacked versions

## Collection

Seeds are collected using scripts in `data/collection/`:

```bash
# Collect GitHub issues with comments
python data/collection/collect_github.py --repo pytorch/pytorch --limit 10 --with-comments

# Check collected seeds
ls data/seeds/github_issue/
cat data/seeds/github_issue/api_manifest.json
```

See `data/collection/README.md` for complete collection guide.

## Validation

To validate seed structure:

```bash
# Validate JSON
python -m json.tool data/seeds/github_issue/api_001_issue_*.json

# Check manifest integrity
python -c "
import json
manifest = json.load(open('data/seeds/github_issue/api_manifest.json'))
print(f'Repository: {manifest[\"repository\"]}')
print(f'Total issues: {manifest[\"collection_info\"][\"total_issues\"]}')
print(f'Files: {len(manifest[\"files\"])} entries')
"

# Verify files exist
python -c "
import json
from pathlib import Path
manifest = json.load(open('data/seeds/github_issue/api_manifest.json'))
for entry in manifest['files']:
    issue_file = Path('data/seeds/github_issue') / entry['issue_file']
    assert issue_file.exists(), f'Missing: {issue_file}'
    if 'comments_file' in entry:
        comments_file = Path('data/seeds/github_issue') / entry['comments_file']
        assert comments_file.exists(), f'Missing: {comments_file}'
print('✓ All files verified')
"
```
