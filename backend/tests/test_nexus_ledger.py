"""NEXUS ledger helpers (Chainalysis-style mobile money graph)."""
from app.services.nexus_ledger import LEDGER_EDGE, account_normalized_key


def test_account_normalized_key_is_partner_scoped():
    assert account_normalized_key("mtn_momo", "protected-ref-abc") == "pdr-account:mtn_momo:protected-ref-abc"


def test_ledger_edge_type_constant():
    assert LEDGER_EDGE == "pdr_transfer"