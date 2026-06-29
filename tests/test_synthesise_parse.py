"""Synthesise output-contract parsing: bounds enforced, truncation recovered, failure
modes named, and recovered/valid counts reported. No model, no podman.

_parse_payloads returns (payloads, status, recovered): status is categorical, recovered
is the count of complete objects salvaged before validation, len(payloads) is how many
then passed it.
"""
from __future__ import annotations

from stages.synthesise import _MAX_PAYLOADS, _MAX_VALUE_LEN, _parse_payloads


def test_clean_json_is_ok():
    text = '{"hypothesis_id":"h","payloads":[{"value":"../../etc/passwd","category":"baseline"}]}'
    items, status, _ = _parse_payloads(text, "h")
    assert status == "ok"
    assert [i["value"] for i in items] == ["../../etc/passwd"]


def test_truncated_array_is_recovered_with_count():
    # Two complete items then a third cut off mid-object, no closing ] or }.
    text = '{"payloads": [{"value": "a"}, {"value": "b"}, {"value": "c'
    items, status, recovered = _parse_payloads(text, "h")
    assert status == "recovered"
    assert recovered == 2
    assert [i["value"] for i in items] == ["a", "b"]


def test_echoed_schema_then_truncated_answer_picks_the_answer():
    # The prompt schema (with the placeholder value) is echoed and closed, then the real
    # answer truncates. The last array with items wins; the placeholder is dropped.
    text = (
        '{"payloads":[{"value":"the concrete input string","category":"baseline"}]}\n'
        "here is the answer\n"
        '{"payloads":[{"value":"REAL1"},{"value":"REAL2'
    )
    items, status, _ = _parse_payloads(text, "h")
    assert status == "recovered"
    assert [i["value"] for i in items] == ["REAL1"]


def test_empty_array_is_empty():
    items, status, _ = _parse_payloads('{"payloads": []}', "h")
    assert status == "empty"
    assert items == []


def test_no_array_is_unparseable():
    items, status, _ = _parse_payloads("no json object here at all", "h")
    assert status == "unparseable"
    assert items == []


def test_items_present_but_none_valid_is_schema_invalid():
    # A closed array whose only element has a non-string value: parsed fine, but nothing
    # usable. Distinct from "empty" (model produced no payloads).
    items, status, recovered = _parse_payloads('{"payloads":[{"value":123}]}', "h")
    assert status == "schema_invalid"
    assert recovered == 1
    assert items == []


def test_payload_count_is_bounded():
    n = _MAX_PAYLOADS + 3
    inner = ",".join(f'{{"value":"p{i}"}}' for i in range(n))
    items, status, recovered = _parse_payloads(f'{{"payloads":[{inner}]}}', "h")
    assert status == "ok"
    assert recovered == n          # all complete objects are counted
    assert len(items) == _MAX_PAYLOADS  # but the kept set is bounded


def test_overlong_value_is_dropped():
    long_value = "a" * (_MAX_VALUE_LEN + 50)
    text = f'{{"payloads":[{{"value":"{long_value}"}},{{"value":"short"}}]}}'
    items, status, _ = _parse_payloads(text, "h")
    assert [i["value"] for i in items] == ["short"]
