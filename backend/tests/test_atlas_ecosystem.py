from app.services.atlas_graph import (
    ATLAS_SCOPED_TABLES,
    FIR_TABLES,
    PDR_TABLES,
    SHARED_TABLES,
    atlas_row_matches_search,
    atlas_source,
)
def test_atlas_scoped_tables_cover_fir_pdr_shared():
    assert "community_entities" in SHARED_TABLES
    assert "fir_reports" in FIR_TABLES
    assert "partner_transactions" in PDR_TABLES
    assert ATLAS_SCOPED_TABLES == FIR_TABLES | PDR_TABLES | SHARED_TABLES
    assert "users" not in ATLAS_SCOPED_TABLES


def test_atlas_source_classification():
    assert atlas_source("fir_reports") == "fir"
    assert atlas_source("partner_accounts") == "pdr"
    assert atlas_source("entity_relationships") == "shared"


def test_atlas_row_matches_search_by_column_and_id():
    values = {"id": "abc-123", "subject": "Suspicious transfer"}
    assert atlas_row_matches_search("fir_reports", values, escaped="transfer")
    assert not atlas_row_matches_search("fir_reports", values, escaped="missing")
    assert atlas_row_matches_search("fir_reports", values, escaped=None, record_ids={"abc-123"})
    assert not atlas_row_matches_search("fir_reports", values, escaped=None, record_ids={"other"})