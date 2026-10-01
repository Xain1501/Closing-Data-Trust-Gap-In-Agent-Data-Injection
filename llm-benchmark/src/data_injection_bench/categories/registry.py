"""Category handler registry."""

from typing import Dict

from ..bench_types import Category
from .base import CategoryHandler
from .github_comments import GitHubCommentsCategory
from .github_issue import GitHubIssueCategory
from .reference_json import ReferenceJSONCategory
from .cloud_drive import CloudDriveCategory
from .email import EmailCategory
from .calendar import CalendarCategory
from .web_dom import WebDOMCategory


_HANDLERS: Dict[Category, CategoryHandler] = {
    Category.GITHUB_COMMENTS: GitHubCommentsCategory(),
    Category.GITHUB_ISSUE: GitHubIssueCategory(),
    Category.REFERENCE_JSON: ReferenceJSONCategory(),
    Category.CLOUD_DRIVE: CloudDriveCategory(),
    Category.EMAIL: EmailCategory(),
    Category.CALENDAR: CalendarCategory(),
    Category.WEB_DOM: WebDOMCategory(),
}


def get_category_handler(category: Category) -> CategoryHandler:
    handler = _HANDLERS.get(category)
    if not handler:
        raise NotImplementedError(f"Category {category} not yet implemented")
    return handler
