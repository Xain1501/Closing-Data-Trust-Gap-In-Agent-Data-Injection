# \#{{ number }} {{ title }}

## Metadata
- Repository: {{ owner }}/{{ repo }}
- Issue URL: {{ html_url }}
- State: {{ state }}
- Author: {{ author }}
- Author Association: {{ author_association | default("none") }}
- Created At: {{ created_at }}
- Last Updated: {{ updated_at }}
- Comments: {{ comments }}
- Labels: {{ labels | default("none") }}

## Description
{{ body | default("*No description provided*") | markdown }}

## Status
- State: {{ state }}
- Assignees: {{ assignees | default("none") }}
- Closed At: {{ closed_at | default("not closed") }}
- State Reason: {{ state_reason | default("none") }}

{% if reactions %}
## Reactions
{% for key, value in reactions.items() %}
- {{ key }}: {{ value }}
{% endfor %}
{% endif %}
