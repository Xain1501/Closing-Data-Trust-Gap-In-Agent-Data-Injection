import pytest

from scripts.evaluate_unseen_attack_family import prepare_family_holdout


def _row(case_id, label, group, split, family=None):
    return {
        "case_id": case_id,
        "classification_unit": "run",
        "label": label,
        "group_id": group,
        "split": split,
        "attack_family": family,
    }


def test_family_holdout_moves_its_matched_clean_group_out_of_training():
    train = [
        _row("new-attack", "attack", "new-task", "train", "important_instructions"),
        _row("new-clean", "benign", "new-task", "train"),
        _row("known-attack", "attack", "known-task", "train", "known_family"),
        _row("known-clean", "benign", "clean-task", "train"),
    ]
    test = [
        _row("heldout-benign", "benign", "test-clean", "test"),
    ]

    adjusted_train, adjusted_test, heldout_groups = prepare_family_holdout(
        train, test, "important_instructions"
    )

    assert heldout_groups == {"new-task"}
    assert {row["case_id"] for row in adjusted_train} == {
        "known-attack", "known-clean"
    }
    assert {row["case_id"] for row in adjusted_test} == {
        "new-attack", "new-clean", "heldout-benign"
    }
    assert not any(
        row.get("attack_family") == "important_instructions"
        for row in adjusted_train
    )


def test_family_holdout_rejects_split_group_leakage():
    train = [
        _row("attack", "attack", "same-group", "train", "new_family"),
        _row("benign", "benign", "train-clean", "train"),
    ]
    test = [
        _row("test-row", "benign", "same-group", "test"),
        _row("test-attack", "attack", "other-attack", "test", "known_family"),
    ]

    with pytest.raises(ValueError, match="groups overlap"):
        prepare_family_holdout(train, test, "new_family")


def test_family_holdout_requires_family_and_both_labels():
    train = [
        _row("attack", "attack", "known", "train", "known_family"),
        _row("benign", "benign", "clean", "train"),
    ]
    test = [
        _row("test-benign", "benign", "test-clean", "test"),
    ]

    with pytest.raises(ValueError, match="is absent"):
        prepare_family_holdout(train, test, "new_family")

