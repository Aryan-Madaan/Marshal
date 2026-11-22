"""LanceDB connector (embedded or LanceDB Cloud).

    import lancedb
    from marshal_ai.connectors.lancedb import from_lancedb

    table = lancedb.connect("./kb.lance").open_table("chunks")
    retriever = from_lancedb(table, embed=my_embedder)

Runs `table.search(vector).where(sql, prefilter=True).limit(k)`, so the
filter is applied *before* the nearest-neighbour search and k results are
still returned when most rows are filtered out. LanceDB takes the filter
as a SQL string, which makes it the one connector where escaping is
Marshal's job: every identifier segment is restricted to a plain name by
the filter translator and backtick-quoted, string values are single-quoted
with embedded quotes doubled, and only finite numbers and booleans are
emitted bare. Nested metadata (a struct column) is addressed with dotted
fields. Verified against lancedb 0.25. Requires the `[lancedb]` extra.
"""

from __future__ import annotations

import math
from typing import Any, Optional

from marshal_ai.connectors._common import Embed, make_document, vector_of
from marshal_ai.connectors._filters import Clause, UnsupportedFilter, prefixed, try_parse
from marshal_ai.retrieval import Document, Retriever


def _literal(value: Any) -> str:
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise UnsupportedFilter("non-finite numbers can't be filtered on")
        return repr(value)
    return "'" + str(value).replace("'", "''") + "'"


def _column(path: str) -> str:
    return ".".join(f"`{segment}`" for segment in path.split("."))


def to_sql(clauses: list[Clause], prefix: Optional[str]) -> str:
    parts = []
    for c in clauses:
        column = _column(prefixed(c.field, prefix))
        if c.op == "eq":
            parts.append(f"{column} = {_literal(c.values[0])}")
        else:
            parts.append(f"{column} IN ({', '.join(_literal(v) for v in c.values)})")
    return " AND ".join(parts)


def from_lancedb(
    table: Any,
    embed: Embed,
    id_column: str = "id",
    text_column: str = "text",
    vector_column: str = "vector",
    metadata_column: Optional[str] = "metadata",
) -> Retriever:
    def _retriever(query: str, k: int, filter: Optional[dict[str, Any]] = None) -> list[Document]:
        if k <= 0:
            return []
        search = table.search(vector_of(embed, query), vector_column_name=vector_column)
        clauses = try_parse(filter)
        if clauses:
            try:
                search = search.where(to_sql(clauses, metadata_column), prefilter=True)
            except UnsupportedFilter:
                pass
        documents = []
        for row in search.limit(k).to_list():
            row = dict(row)
            distance = row.pop("_distance", None)
            row.pop(vector_column, None)
            doc_id = row.pop(id_column, None)
            documents.append(make_document(doc_id, row, text_column, metadata_column, score=distance))
        return documents

    return _retriever
