"""Category handlers."""

from .base import AttackPlan, BaseCategoryHandler, CategoryHandler
from .registry import get_category_handler
from .github_issue import GitHubIssueCategory
from .reference_json import ReferenceJSONCategory
from .cloud_drive import CloudDriveCategory
from .email import EmailCategory
from .calendar import CalendarCategory
from .web_dom import WebDOMCategory

__all__ = [
    "AttackPlan",
    "BaseCategoryHandler",
    "CategoryHandler",
    "get_category_handler",
    "GitHubIssueCategory",
    "ReferenceJSONCategory",
    "CloudDriveCategory",
    "EmailCategory",
    "CalendarCategory",
    "WebDOMCategory",
]
