"""
Tests for package.rule_order_functions module.

Covers: sorted_rule_order, build_swap_map, build_renumber_map,
        build_resequence_map, apply_renumber_map
"""

import pytest

from package.rule_order_functions import (
    MAX_RULE_NUMBER,
    apply_renumber_map,
    build_renumber_map,
    build_resequence_map,
    build_swap_map,
    sorted_rule_order,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _chain(rule_order, extra=None):
    """Flat chain layout: rules are siblings of rule-order and default."""
    chain = {
        "rule-order": list(rule_order),
        "default": {"default_action": "drop"},
    }
    for rule in rule_order:
        chain[rule] = {"description": f"rule {rule}"}
    if extra:
        chain.update(extra)
    return chain


def _filter(rule_order):
    """Nested filter layout: rules live under a rules key."""
    return {
        "rule-order": list(rule_order),
        "description": "Input filter",
        "rules": {rule: {"description": f"rule {rule}"} for rule in rule_order},
    }


# ===================================================================
# sorted_rule_order
# ===================================================================


class TestSortedRuleOrder:
    def test_sorts_numerically_not_lexically(self):
        assert sorted_rule_order(["100", "20", "3"]) == ["3", "20", "100"]

    def test_empty_list(self):
        assert sorted_rule_order([]) == []


# ===================================================================
# build_swap_map
# ===================================================================


class TestBuildSwapMap:
    def test_swap_up(self):
        assert build_swap_map(["10", "20", "30"], "20", "up") == {
            "20": "10",
            "10": "20",
        }

    def test_swap_down(self):
        assert build_swap_map(["10", "20", "30"], "20", "down") == {
            "20": "30",
            "30": "20",
        }

    def test_first_rule_up_returns_none(self):
        assert build_swap_map(["10", "20"], "10", "up") is None

    def test_last_rule_down_returns_none(self):
        assert build_swap_map(["10", "20"], "20", "down") is None

    def test_single_rule_returns_none(self):
        assert build_swap_map(["10"], "10", "up") is None
        assert build_swap_map(["10"], "10", "down") is None

    def test_unsorted_input_uses_numeric_order(self):
        # "100" sorts before "20" lexically but after it numerically
        assert build_swap_map(["100", "20"], "100", "up") == {
            "100": "20",
            "20": "100",
        }

    def test_unknown_rule_raises(self):
        with pytest.raises(ValueError):
            build_swap_map(["10", "20"], "99", "up")

    def test_unknown_direction_raises(self):
        with pytest.raises(ValueError):
            build_swap_map(["10", "20"], "10", "sideways")


# ===================================================================
# build_renumber_map
# ===================================================================


class TestBuildRenumberMap:
    def test_move_to_free_number(self):
        assert build_renumber_map(["10", "20"], "10", "50") == {"10": "50"}

    def test_taken_number_shifts_occupant(self):
        assert build_renumber_map(["10", "20"], "10", "20") == {
            "10": "20",
            "20": "21",
        }

    def test_cascade_stops_at_first_gap(self):
        assert build_renumber_map(["10", "20", "21", "30"], "10", "20") == {
            "10": "20",
            "20": "21",
            "21": "22",
        }

    def test_rules_below_target_untouched(self):
        assert build_renumber_map(["10", "20", "30"], "30", "20") == {
            "30": "20",
            "20": "21",
        }

    def test_same_number_raises(self):
        with pytest.raises(ValueError):
            build_renumber_map(["10"], "10", "10")

    def test_non_integer_raises(self):
        with pytest.raises(ValueError):
            build_renumber_map(["10"], "10", "abc")

    def test_zero_raises(self):
        with pytest.raises(ValueError):
            build_renumber_map(["10"], "10", "0")

    def test_above_maximum_raises(self):
        with pytest.raises(ValueError):
            build_renumber_map(["10"], "10", str(MAX_RULE_NUMBER + 1))

    def test_shift_past_maximum_raises(self):
        with pytest.raises(ValueError):
            build_renumber_map(["10", str(MAX_RULE_NUMBER)], "10", str(MAX_RULE_NUMBER))

    def test_unknown_rule_raises(self):
        with pytest.raises(ValueError):
            build_renumber_map(["10"], "99", "50")


# ===================================================================
# build_resequence_map
# ===================================================================


class TestBuildResequenceMap:
    def test_renumbers_by_step(self):
        assert build_resequence_map(["1", "2", "3"]) == {
            "1": "10",
            "2": "20",
            "3": "30",
        }

    def test_only_includes_changed_rules(self):
        assert build_resequence_map(["10", "25", "30"]) == {"25": "20"}

    def test_already_sequenced_is_empty(self):
        assert build_resequence_map(["10", "20", "30"]) == {}

    def test_empty_order_is_empty(self):
        assert build_resequence_map([]) == {}

    def test_preserves_relative_order(self):
        assert build_resequence_map(["5", "100", "7"]) == {
            "5": "10",
            "7": "20",
            "100": "30",
        }

    def test_custom_step(self):
        assert build_resequence_map(["1", "2"], step=100) == {
            "1": "100",
            "2": "200",
        }

    def test_too_many_rules_raises(self):
        with pytest.raises(ValueError):
            build_resequence_map([str(n) for n in range(1, 12)], step=MAX_RULE_NUMBER)


# ===================================================================
# apply_renumber_map
# ===================================================================


class TestApplyRenumberMap:
    def test_swap_does_not_clobber(self):
        chain = _chain(["10", "20"])
        apply_renumber_map(chain, chain, {"10": "20", "20": "10"})

        assert chain["rule-order"] == ["10", "20"]
        assert chain["10"]["description"] == "rule 20"
        assert chain["20"]["description"] == "rule 10"

    def test_cascade_applies_in_full(self):
        chain = _chain(["10", "20", "21"])
        apply_renumber_map(chain, chain, {"10": "20", "20": "21", "21": "22"})

        assert chain["rule-order"] == ["20", "21", "22"]
        assert chain["20"]["description"] == "rule 10"
        assert chain["21"]["description"] == "rule 20"
        assert chain["22"]["description"] == "rule 21"

    def test_rule_order_is_numerically_sorted(self):
        chain = _chain(["10", "20"])
        apply_renumber_map(chain, chain, {"10": "100"})

        assert chain["rule-order"] == ["20", "100"]

    def test_reserved_chain_keys_untouched(self):
        chain = _chain(["10"])
        apply_renumber_map(chain, chain, {"10": "50"})

        assert chain["default"] == {"default_action": "drop"}
        assert "rule-order" in chain

    def test_nested_filter_layout(self):
        fw_filter = _filter(["10", "20"])
        apply_renumber_map(fw_filter["rules"], fw_filter, {"10": "20", "20": "10"})

        assert fw_filter["rule-order"] == ["10", "20"]
        assert fw_filter["rules"]["10"]["description"] == "rule 20"
        assert fw_filter["rules"]["20"]["description"] == "rule 10"
        assert fw_filter["description"] == "Input filter"

    def test_empty_map_is_noop(self):
        chain = _chain(["10", "20"])
        apply_renumber_map(chain, chain, {})

        assert chain["rule-order"] == ["10", "20"]
        assert chain["10"]["description"] == "rule 10"
