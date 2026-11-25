"""Build the ATLAS unified FIR + PDR + shared intelligence ecosystem graph."""
from __future__ import annotations

from typing import Any, Literal

from sqlalchemy import String, func, or_, select

from app.core.config import Settings, get_settings
from app.models import Base, Partner
from app.services.nexus_pdr_search import search_pdr_identifiers
from app.services.atlas_graph import (
    ATLAS_SCOPED_TABLES,
    ATLAS_TABLE_LOAD_ORDER,
    atlas_attach_entity_relationships,
    atlas_attach_foreign_keys,
    atlas_attach_pdr_projections,
    atlas_attach_transaction_links,
    atlas_filter_statements,
    atlas_record,
    atlas_row_matches_search,
    atlas_semantic_relationships,
    atlas_source,
)


def _chosen_tables(
    table_name: str,
    source_filter: str,
    record_type: str | None,
) -> list[str]:
    if table_name != "all":
        return [table_name] if table_name in ATLAS_SCOPED_TABLES else []
    chosen = [name for name in ATLAS_TABLE_LOAD_ORDER if name in ATLAS_SCOPED_TABLES]
    if source_filter != "all":
        chosen = [name for name in chosen if atlas_source(name) == source_filter]
    if record_type:
        chosen = [name for name in chosen if name == record_type]
    return chosen


async def _count_table(
    db,
    table,
    table_name: str,
    *,
    escaped: str | None,
    risk_level: str | None,
    verification_status: str | None,
    date_from: str | None,
    date_to: str | None,
    record_ids: set[str] | None = None,
) -> int:
    ok, filters, reason = atlas_filter_statements(
        table, table_name, risk_level=risk_level, verification_status=verification_status,
        date_from=date_from, date_to=date_to, escaped=escaped, record_ids=record_ids,
    )
    if not ok and reason == "skip":
        return 0
    count_statement = select(func.count()).select_from(table)
    if filters:
        count_statement = count_statement.where(*filters)
    return int((await db.scalar(count_statement)) or 0)


async def _load_table_rows(
    db,
    table,
    table_name: str,
    *,
    escaped: str | None,
    risk_level: str | None,
    verification_status: str | None,
    date_from: str | None,
    date_to: str | None,
    row_limit: int | None,
    offset: int = 0,
    record_ids: set[str] | None = None,
) -> list[dict]:
    ok, filters, reason = atlas_filter_statements(
        table, table_name, risk_level=risk_level, verification_status=verification_status,
        date_from=date_from, date_to=date_to, escaped=escaped, record_ids=record_ids,
    )
    if not ok and reason == "skip":
        return []
    statement = select(table).order_by(table.c.id)
    if filters:
        statement = statement.where(*filters)
    if offset:
        statement = statement.offset(offset)
    if row_limit is not None:
        statement = statement.limit(row_limit)
    return [dict(row) for row in (await db.execute(statement)).mappings().all()]


async def build_atlas_network_graph(
    db,
    *,
    query: str | None,
    table_name: str,
    source_filter: Literal["all", "fir", "pdr", "shared"],
    record_type: str | None,
    risk_level: str | None,
    verification_status: str | None,
    date_from: str | None,
    date_to: str | None,
    relationship_type: str | None,
    limit: int,
    offset: int,
    coverage: Literal["ecosystem", "sample"] = "ecosystem",
    settings: Settings | None = None,
) -> dict[str, Any]:
    """
    ecosystem: load every row in scoped FIR/PDR/shared tables (subject to max_nodes).
    sample: legacy paged slice per table (small preview).
    """
    tables = Base.metadata.tables
    chosen = _chosen_tables(table_name, source_filter, record_type)
    if not chosen:
        return _empty_response(table_name, offset, limit, coverage, query, source_filter, record_type,
                               risk_level, verification_status, date_from, date_to, relationship_type)

    search = query.strip() if query and query.strip() else None
    escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") if search else None
    protected_match_ids: dict[str, set[str]] = {}
    if search:
        pdr_matches = await search_pdr_identifiers(
            db, settings or get_settings(), search, include_fir=False,
        )
        table_for_kind = {
            "identity": "partner_identities",
            "account": "partner_accounts",
            "transaction": "partner_transactions",
        }
        for match in pdr_matches.get("items", []):
            source_table = table_for_kind.get(str(match.get("kind")))
            if source_table and match.get("record_id"):
                protected_match_ids.setdefault(source_table, set()).add(str(match["record_id"]))
    scoped_total = 0
    for table_key in ATLAS_SCOPED_TABLES:
        if table_key not in tables:
            continue
        scoped_total += int((await db.scalar(select(func.count()).select_from(tables[table_key]))) or 0)

    nodes: dict[str, dict] = {}
    raw_rows: dict[str, dict[str, dict]] = {}
    counts: dict[str, int] = {}
    total_matching = 0
    remaining = limit
    truncated = False

    use_ecosystem = coverage == "ecosystem" and table_name == "all" and offset == 0

    for name in chosen:
        if name not in tables:
            continue
        table = tables[name]
        counts[name] = await _count_table(
            db, table, name, escaped=escaped, risk_level=risk_level,
            verification_status=verification_status, date_from=date_from, date_to=date_to,
            record_ids=protected_match_ids.get(name),
        )
        total_matching += counts[name]
        if counts[name] == 0:
            continue

        if use_ecosystem:
            if remaining <= 0:
                truncated = True
                continue
            row_limit = min(counts[name], remaining)
            rows = await _load_table_rows(
                db, table, name, escaped=escaped, risk_level=risk_level,
                verification_status=verification_status, date_from=date_from, date_to=date_to,
                row_limit=row_limit, record_ids=protected_match_ids.get(name),
            )
            if len(rows) < counts[name]:
                truncated = True
            remaining -= len(rows)
        else:
            page_size = limit if table_name != "all" else max(1, limit // max(len(chosen), 1))
            rows = await _load_table_rows(
                db, table, name, escaped=escaped, risk_level=risk_level,
                verification_status=verification_status, date_from=date_from, date_to=date_to,
                row_limit=page_size, offset=offset if table_name != "all" else 0,
                record_ids=protected_match_ids.get(name),
            )
            if table_name == "all" and counts[name] > offset + page_size:
                truncated = True

        for values in rows:
            node = atlas_record(name, values)
            protected = protected_match_ids.get(name, set())
            node["search_match"] = atlas_row_matches_search(
                name, values, escaped=escaped, record_ids=protected or None,
            )
            node["search_match_priority"] = 0 if str(values.get("id")) in protected else 1
            nodes[node["id"]] = node
            raw_rows.setdefault(name, {})[node["record_id"]] = values

    edges: dict[tuple[str, str, str], dict] = {}
    fetch_budget = max(limit * 2, 2000)
    await atlas_attach_foreign_keys(db, raw_rows, nodes, edges, fetch_budget=fetch_budget)

    # Table-scoped browse: inbound FK neighborhood.
    if table_name != "all" and raw_rows.get(table_name):
        selected_ids = set(raw_rows[table_name])
        related_budget = limit
        for child_name, child_table in tables.items():
            if child_name not in ATLAS_SCOPED_TABLES or related_budget <= 0:
                continue
            for column in child_table.columns:
                if related_budget <= 0:
                    break
                if not any(fk.column.table.name == table_name for fk in column.foreign_keys):
                    continue
                related_rows = (await db.execute(select(child_table).where(
                    column.cast(String).in_(selected_ids)
                ).limit(related_budget))).mappings().all()
                for row in related_rows:
                    values = dict(row)
                    child_node = atlas_record(child_name, values)
                    nodes.setdefault(child_node["id"], child_node)
                    raw_rows.setdefault(child_name, {}).setdefault(child_node["record_id"], values)
                    child_id = f"{atlas_source(child_name)}.{child_name}:{values['id']}"
                    parent_id = f"{atlas_source(table_name)}.{table_name}:{values[column.name]}"
                    key = (child_id, parent_id, column.name)
                    edges[key] = {
                        "source": child_id, "target": parent_id,
                        "relationship": column.name.removesuffix("_id").replace("_", " "),
                        "confidence": 1.0, "repository": atlas_source(child_name),
                        "source_table": child_name, "source_record_id": str(values["id"]),
                        "verification_status": "database_foreign_key",
                    }
                    related_budget -= 1

    partner_codes = {
        str(row.id): row.partner_code
        for row in (await db.scalars(select(Partner))).all()
    }
    await atlas_attach_pdr_projections(db, raw_rows, nodes, edges, partner_codes)
    await atlas_attach_transaction_links(db, raw_rows, nodes, edges)
    atlas_attach_entity_relationships(raw_rows, nodes, edges)

    for link in atlas_semantic_relationships(raw_rows, nodes):
        key = (link["source"], link["target"],
               f"{link['source_table']}:{link['source_record_id']}:{link['relationship']}")
        edges[key] = link

    if search:
        for node_id, node in list(nodes.items()):
            if node.get("search_match"):
                continue
            table_name = node.get("table")
            record_id = node.get("record_id")
            if not table_name or record_id is None:
                continue
            values = raw_rows.get(table_name, {}).get(str(record_id))
            if values is None:
                continue
            if atlas_row_matches_search(
                table_name,
                values,
                escaped=escaped,
                record_ids=protected_match_ids.get(table_name) or None,
            ):
                node["search_match"] = True
                if str(record_id) in protected_match_ids.get(table_name, set()):
                    node["search_match_priority"] = 0

    by_source = {"fir": 0, "pdr": 0, "shared": 0}
    for node in nodes.values():
        by_source[node["source"]] += 1
    edge_items = list(edges.values())
    if relationship_type:
        edge_items = [edge for edge in edge_items
                      if edge["relationship"].casefold() == relationship_type.casefold()]

    default_page = limit if table_name != "all" else (limit if use_ecosystem else max(1, limit // max(len(chosen), 1)))
    has_more = False
    if not use_ecosystem and table_name == "all":
        has_more = any(count > offset + default_page for count in counts.values())
    elif not use_ecosystem and table_name != "all":
        has_more = counts.get(table_name, 0) > offset + default_page

    return {
        "nodes": list(nodes.values()),
        "edges": edge_items,
        "summary": {
            "node_count": len(nodes),
            "edge_count": len(edge_items),
            "by_source": by_source,
            "table": table_name,
            "offset": offset,
            "limit": limit,
            "page_size": default_page,
            "matched_records": total_matching if search or risk_level or verification_status or date_from or date_to else scoped_total,
            "scoped_record_total": scoped_total,
            "nodes_loaded": len(nodes),
            "query": search,
            "has_more": has_more,
            "truncated": truncated and use_ecosystem,
            "coverage": coverage if table_name == "all" else "table",
            "ecosystem_complete": use_ecosystem and not truncated,
            "record_counts_by_table": counts,
            "scoped_table_count": len(ATLAS_SCOPED_TABLES),
            "filters": {
                "source": source_filter, "type": record_type, "risk_level": risk_level,
                "verification_status": verification_status, "date_from": date_from,
                "date_to": date_to, "relationship_type": relationship_type,
            },
        },
    }


def _empty_response(table_name, offset, limit, coverage, query, source_filter, record_type,
                    risk_level, verification_status, date_from, date_to, relationship_type):
    return {
        "nodes": [], "edges": [],
        "summary": {
            "node_count": 0, "edge_count": 0,
            "by_source": {"fir": 0, "pdr": 0, "shared": 0},
            "table": table_name, "offset": offset, "limit": limit,
            "matched_records": 0, "scoped_record_total": 0, "nodes_loaded": 0,
            "query": query, "has_more": False, "truncated": False,
            "coverage": coverage, "ecosystem_complete": False,
            "record_counts_by_table": {}, "scoped_table_count": len(ATLAS_SCOPED_TABLES),
            "filters": {
                "source": source_filter, "type": record_type, "risk_level": risk_level,
                "verification_status": verification_status, "date_from": date_from,
                "date_to": date_to, "relationship_type": relationship_type,
            },
        },
    }
