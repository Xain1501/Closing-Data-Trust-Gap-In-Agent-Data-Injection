# GitHub Issue Comments ({{ total }})
{% if total == 0 %}
*No comments*
{% else %}
{% for comment in comments %}
**{{ comment.author }} ({{ comment.author_association | default("unknown") }}) {{ comment.created_at }}**

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
