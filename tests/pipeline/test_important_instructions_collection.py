import json
from types import SimpleNamespace

import pytest

from scripts.collect_important_instructions import (
    BudgetLedger,
    CollectionStopped,
    _rate_limit_delay,
)


def test_budget_refuses_request_before_it_can_exceed_cap(tmp_path):
    ledger_path = tmp_path / "budget.json"
    ledger = BudgetLedger(ledger_path, cap_usd=0.001)

    with pytest.raises(CollectionStopped, match="reserved-spend cap"):
        ledger.reserve(100)

    assert ledger.requests == 0
    assert json.loads(ledger_path.read_text(encoding="utf-8"))["maximum_exposure_usd"] == 0


def test_uncertain_request_keeps_full_reservation_in_exposure(tmp_path):
    request_cost = BudgetLedger.estimate_max_cost(100)
    ledger = BudgetLedger(tmp_path / "budget.json", cap_usd=request_cost * 1.5)

    reservation = ledger.reserve(100)
    ledger.mark_uncertain(reservation)

    with pytest.raises(CollectionStopped, match="reserved-spend cap"):
        ledger.reserve(100)

    assert ledger.requests == 1
    assert ledger.uncertain_usd == reservation
    assert ledger.pending_usd == 0


def test_successful_usage_reconciles_reserved_cost(tmp_path):
    ledger = BudgetLedger(tmp_path / "budget.json")

    reservation = ledger.reserve(100)
    ledger.settle(reservation, prompt_tokens=100, completion_tokens=50)

    assert ledger.actual_usd == pytest.approx((100 * 0.15 + 50 * 0.60) / 1_000_000)
    assert ledger.pending_usd == 0
    assert ledger.uncertain_usd == 0
    assert ledger.prompt_tokens == 100
    assert ledger.completion_tokens == 50


def test_resume_preserves_uncertain_provider_exposure(tmp_path):
    ledger_path = tmp_path / "budget.json"
    request_cost = BudgetLedger.estimate_max_cost(100)
    ledger = BudgetLedger(ledger_path, cap_usd=request_cost * 1.5)
    reservation = ledger.reserve(100)
    ledger.mark_uncertain(reservation)

    resumed = BudgetLedger(ledger_path, cap_usd=request_cost * 1.5, resume=True)

    assert resumed.requests == 1
    assert resumed.uncertain_usd == reservation
    with pytest.raises(CollectionStopped, match="reserved-spend cap"):
        resumed.reserve(100)


def test_rate_limit_delay_uses_provider_retry_message():
    class RateLimitErrorStub:
        def __init__(self):
            self.response = SimpleNamespace(headers={})
            self.message = "Rate limit reached. Try again in 8.55s."

        def __str__(self):
            return self.message

    assert _rate_limit_delay(RateLimitErrorStub()) == 8.55
