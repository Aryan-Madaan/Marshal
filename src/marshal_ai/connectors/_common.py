"""Helpers shared by the connectors."""

from __future__ import annotations

from typing import Any, Callable, Optional

from marshal_ai.retrieval import Document

Embed = Callable[[str], "list[float]"]


def make_document(
    doc_id: Any,
    record: dict[str, Any],
    text_field: str,
    metadata_field: Optional[str],
    exclude: tuple[str, ...] = (),
    score: Optional[float] = None,
) -> Document:
    """Build a `Document` from a store record. With `metadata_field`, the
    metadata is that nested object; without it, every top-level field
    except the text, the id and anything in `exclude` (e.g. the vector)."""
    record = dict(record or {})
    content = record.get(text_field)
    if metadata_field:
        metadata = record.get(metadata_field) or {}
        metadata = dict(metadata) if isinstance(metadata, dict) else {}
    else:
        metadata = {k: v for k, v in record.items() if k not in (text_field, *exclude)}
    return Document(
        id=str(doc_id),
        content=content if isinstance(content, str) else ("" if content is None else str(content)),
        metadata=metadata,
        score=score,
    )


def vector_of(embed: Embed, query: str) -> list[float]:
    vector = embed(query)
    return [float(x) for x in vector]
