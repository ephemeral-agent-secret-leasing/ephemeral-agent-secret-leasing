from __future__ import annotations

import base64
from urllib.parse import quote

from hypothesis import given, settings
from hypothesis import strategies as st

from ephemeral_agent_secret_leasing.taint import TaintRegistry, encodings_for


def test_supported_encodings_detected() -> None:
    secret = "lease_secret_AbCdEfGh1234567890"
    reg = TaintRegistry()
    reg.register("l1", secret)
    for name, encoded in encodings_for(secret).items():
        assert reg.scan_text(f"prefix {encoded} suffix") is not None, name
    assert reg.scan_text("lease_secret_.AbCdEfGh.1234567890") is not None
    assert (
        reg.scan_request(
            {"url": "https://lease_secret_.AbCdEfGh.1234567890.collector.example.net/x"}
        )
        is not None
    )


@given(
    st.text(
        alphabet=st.characters(
            min_codepoint=33, max_codepoint=126, blacklist_characters=['"', "\\"]
        ),
        min_size=8,
        max_size=48,
    ),
    st.sampled_from(["raw", "base64", "base64url", "hex", "percent", "reversed", "json"]),
    st.text(min_size=0, max_size=40),
)
@settings(max_examples=200, deadline=None)
def test_property_any_registered_value_embedding_detected(
    secret: str, encoding: str, pad: str
) -> None:
    reg = TaintRegistry()
    reg.register("lease", secret)
    assert reg.scan_text(pad + encodings_for(secret)[encoding] + pad) is not None


def test_false_positive_on_benign_corpus() -> None:
    reg = TaintRegistry()
    reg.register("lease", "lease_secret_1234567890abcdefghijklmnop")
    benign = [base64.b64encode(f"blob-{i}".encode()).decode() for i in range(20)] + [
        quote(
            "ordinary prose with hashes 0123456789abcdef and uuid "
            "550e8400-e29b-41d4-a716-446655440000"
        )
    ]
    assert sum(1 for text in benign if reg.scan_text(text) is not None) == 0
