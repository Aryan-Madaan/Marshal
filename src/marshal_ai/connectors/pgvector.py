"""PostgreSQL + pgvector connector.

    import psycopg
    from marshal_ai.connectors.pgvector import from_pgvector

    conn = psycopg.connect(dsn, autocommit=True)
    retriever = from_pgvector(conn, "kb_chunks", embed=my_embedder)

Expects a table with an id, a text column, a `jsonb` metadata column and
a `vector` column (names configurable). Runs one parameterized query:

    SELECT id, content, metadata, embedding <=> $1::vector AS distance
    FROM kb_chunks WHERE (metadata #>> $2::text[]) = ANY($3::text[])
    ORDER BY distance LIMIT $4

Everything user- or document-controlled is a bound parameter; table and
column names are validated identifiers composed with `psycopg.sql`, never
string-formatted, so neither a query nor a metadata value can inject SQL.

Postgres is the one store here that can *enforce* access in the engine:
put Row-Level Security policies on the table and connect as a role they
apply to, and a bug anywhere above the database still can't return a row
the role can't see. `RetrievalGuard` then becomes the second layer
(audit, redaction, flow labels), not the only one. Verified against
psycopg 3.3 and pgvector on PostgreSQL 17. Requires the `[pgvector]` extra.
"""

from __future__ import annotations

import re
from typing import Any, Literal, Optional

from marshal_ai.connectors._common import vector_of, Embed
from marshal_ai.connectors._filters import try_parse
from marshal_ai.retrieval import Document, Retriever

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
_OPERATORS = {"cosine": "<=>", "l2": "<->", "inner_product": "<#>"}


def _identifier(name: str) -> "tuple[str, ...]":
    parts = tuple(name.split("."))
    if not 1 <= len(parts) <= 2 or not all(_IDENT.match(p) for p in parts):
        raise ValueError(f"invalid SQL identifier {name!r}")
    return parts


def _scalar_text(value: Any) -> str:
    # `metadata->>'key'` yields JSON scalars as text: booleans as
    # true/false, numbers in their JSON form.
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def from_pgvector(
    connection: Any,
    table: str,
    embed: Embed,
    id_column: str = "id",
    text_column: str = "content",
    metadata_column: str = "metadata",
    embedding_column: str = "embedding",
    distance: Literal["cosine", "l2", "inner_product"] = "cosine",
) -> Retriever:
    from psycopg import sql

    if distance not in _OPERATORS:
        raise ValueError(f"distance must be one of {sorted(_OPERATORS)}")
    table_id = sql.Identifier(*_identifier(table))
    cols = {name: sql.Identifier(*_identifier(value)) for name, value in {
        "id": id_column, "text": text_column, "metadata": metadata_column, "embedding": embedding_column,
    }.items()}
    operator = sql.SQL(_OPERATORS[distance])

    def _retriever(query: str, k: int, filter: Optional[dict[str, Any]] = None) -> list[Document]:
        if k <= 0:
            return []
        vector_literal = "[" + ",".join(repr(x) for x in vector_of(embed, query)) + "]"
        params: list[Any] = [vector_literal]
        conditions = []
        for clause in try_parse(filter) or []:
            # A dotted Marshal field becomes a jsonb path, every segment a
            # bound parameter: metadata #>> ARRAY[$a, $b]
            path = clause.field.split(".")
            conditions.append(sql.SQL("({} #>> %s::text[]) = ANY(%s::text[])").format(cols["metadata"]))
            params.extend([path, [_scalar_text(v) for v in clause.values]])
        where = sql.SQL(" WHERE ") + sql.SQL(" AND ").join(conditions) if conditions else sql.SQL("")
        statement = sql.SQL(
            "SELECT {id}, {text}, {metadata}, {embedding} {op} %s::vector AS distance FROM {table}{where} "
            "ORDER BY distance LIMIT %s"
        ).format(op=operator, table=table_id, where=where, **cols)
        params.append(k)
        with connection.cursor() as cursor:
            cursor.execute(statement, params)
            rows = cursor.fetchall()
        return [
            Document(
                id=str(row[0]),
                content=row[1] or "",
                metadata=dict(row[2]) if isinstance(row[2], dict) else {},
                score=float(row[3]) if row[3] is not None else None,
            )
            for row in rows
        ]

    return _retriever
