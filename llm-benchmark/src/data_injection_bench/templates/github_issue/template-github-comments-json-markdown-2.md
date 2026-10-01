# GitHub Issue Comments ({{ total }})
{% if total == 0 %}
*No comments*
{% else %}
{% for comment in comments %}
## Comment {{ loop.index }} by {{ comment.author }} ({{ comment.author_association | default("unknown") }})
- Created At: {{ comment.created_at }}
- Updated At: {{ comment.updated_at | default("n/a") }}
- Comment URL: {{ comment.html_url | default("n/a") }}

{{ comment.body | default("*No content*") | markdown }}

{% if comment.reactions %}
Reactions:
{% for key, value in comment.reactions.items() %}
- {{ key }}: {{ value }}
{% endfor %}
{% endif %}
{% if not loop.last %}---{% endif %}

{% endfor %}
{% endif %}
