"""Retrieval connectors, against real backends wherever one can run:

- Qdrant: the real client's in-process `QdrantClient(":memory:")` mode.
- MongoDB Atlas Vector Search and PostgreSQL+pgvector: real servers, when
  MARSHAL_TEST_MONGODB_URI / MARSHAL_TEST_PG_DSN point at one (CI starts
  `mongodb-atlas-local` and `pgvector/pgvector` service containers);
  skipped otherwise.
- Firestore: the real SDK builds and serializes the query (filters,
  vector, distance measure); only the final network round trip is
  replaced, since the emulator needs a JVM + gcloud.
- Pinecone, Elasticsearch, Weaviate: recording fakes asserting the exact
  request each connector sends.

Every real-backend test drives the connector through `RetrievalGuard`
with `GroupPolicy`, whose pushdown filter must be applied *in the store*
(fewer candidates come back), while `RetrievalGuard` still re-checks.
"""

import os
import time
import uuid

import pytest

from marshal_ai import GroupPolicy, InMemoryAuditSink, Principal, RetrievalGuard
from marshal_ai.connectors._filters import UnsupportedFilter, parse_filter

DOCS = [
    ("hr-1", "salary bands", {"group": "hr", "acl": ["role:hr"]}, [1.0, 0.0, 0.0]),
    ("hr-2", "hiring plan", {"group": "hr", "acl": ["role:hr"]}, [0.9, 0.1, 0.0]),
    ("eng-1", "deploy runbook", {"group": "eng", "acl": ["role:eng"]}, [0.8, 0.2, 0.0]),
    ("pub-1", "holiday calendar", {"group": "public", "acl": ["role:all"]}, [0.7, 0.3, 0.0]),
]


def embed(text: str) -> list[float]:
    return [1.0, 0.0, 0.0]  # every query points at the "hr" corner


HR = Principal("alice", {"hr"})
ENG = Principal("bob", {"eng"})


def _assert_governed(retriever):
    sink = InMemoryAuditSink()
    guard = RetrievalGuard(retriever, policy=GroupPolicy(), audit_sink=sink)
    hr_ids = [d.id for d in guard.retrieve("salary", HR, k=4)]
    eng_ids = [d.id for d in guard.retrieve("salary", ENG, k=4)]
    assert set(hr_ids) == {"hr-1", "hr-2"} and hr_ids[0] == "hr-1"
    assert eng_ids == ["eng-1"]
    # pushed down: the store itself never returned the other groups' documents
    assert [e.candidates_seen for e in sink.all_entries()] == [2, 1]
    doc = guard.retrieve("salary", HR, k=1)[0]
    assert doc.content == "salary bands" and doc.metadata["group"] == "hr" and doc.score is not None


# --- the shared filter translator ---------------------------------------------


def test_filter_dialect_parses_and_rejects_operator_injection():
    clauses = parse_filter({"group": {"$in": ["hr", "eng"]}, "$and": [{"tier": 2}, {"live": {"$eq": True}}]})
    assert [(c.field, c.op, c.values) for c in clauses] == [
        ("group", "in", ("hr", "eng")), ("tier", "eq", (2,)), ("live", "eq", (True,)),
    ]
    for bad in (
        {"group": {"$ne": "hr"}},                 # operator outside the dialect
        {"group": {"$in": [{"$gt": ""}]}},        # a dict smuggled in as a value
        {"$where": "sleep(1000)"},                # not a field name
        {"group; DROP TABLE x": "hr"},            # not an identifier
        {"group": {"$in": []}},
    ):
        with pytest.raises(UnsupportedFilter):
            parse_filter(bad)


# --- Qdrant (real, in-process) -------------------------------------------------


def test_qdrant_real_in_memory():
    pytest.importorskip("qdrant_client")
    from qdrant_client import QdrantClient, models

    from marshal_ai.connectors.qdrant import from_qdrant

    client = QdrantClient(":memory:")
    client.create_collection("kb", vectors_config=models.VectorParams(size=3, distance=models.Distance.COSINE))
    client.upsert("kb", points=[
        models.PointStruct(id=i, vector=vec, payload={"text": text, "metadata": {**meta, "doc_id": doc_id}})
        for i, (doc_id, text, meta, vec) in enumerate(DOCS)
    ])

    def retriever(query, k, filter=None):
        # Qdrant ids must be ints/UUIDs; surface the stable doc id from metadata
        docs = from_qdrant(client, "kb", embed)(query, k, filter=filter)
        for d in docs:
            d.id = d.metadata["doc_id"]
        return docs

    _assert_governed(retriever)


# --- MongoDB Atlas Vector Search (real server) ---------------------------------


@pytest.fixture(scope="module")
def mongo_collection():
    uri = os.environ.get("MARSHAL_TEST_MONGODB_URI")
    if not uri:
        pytest.skip("set MARSHAL_TEST_MONGODB_URI to a mongodb-atlas-local instance")
    pymongo = pytest.importorskip("pymongo")
    from pymongo.operations import SearchIndexModel

    client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5000)
    collection = client["marshal_test"][f"chunks_{uuid.uuid4().hex[:8]}"]
    collection.insert_many([
        {"_id": doc_id, "text": text, "metadata": meta, "embedding": vec} for doc_id, text, meta, vec in DOCS
    ])
    collection.create_search_index(SearchIndexModel(
        name="vector_index", type="vectorSearch",
        definition={"fields": [
            {"type": "vector", "path": "embedding", "numDimensions": 3, "similarity": "cosine"},
            {"type": "filter", "path": "metadata.group"},
        ]},
    ))
    deadline = time.time() + 120
    while time.time() < deadline:
        indexes = list(collection.list_search_indexes("vector_index"))
        if indexes and indexes[0].get("queryable"):
            break
        time.sleep(1)
    else:
        pytest.fail("vector index never became queryable")
    # the index is queryable before every document is indexed; wait for all
    from marshal_ai.connectors.mongodb import from_mongodb_atlas

    probe = from_mongodb_atlas(collection, embed, index="vector_index")
    while time.time() < deadline and len(probe("q", 10)) < len(DOCS):
        time.sleep(1)
    yield collection
    collection.drop()
    client.close()


def test_mongodb_atlas_real_vector_search(mongo_collection):
    from marshal_ai.connectors.mongodb import from_mongodb_atlas

    retriever = from_mongodb_atlas(mongo_collection, embed, index="vector_index")
    _assert_governed(retriever)
    assert "embedding" not in retriever("q", 1)[0].metadata


# --- PostgreSQL + pgvector (real server) ---------------------------------------


@pytest.fixture(scope="module")
def pg_table():
    dsn = os.environ.get("MARSHAL_TEST_PG_DSN")
    if not dsn:
        pytest.skip("set MARSHAL_TEST_PG_DSN to a PostgreSQL with the pgvector extension")
    psycopg = pytest.importorskip("psycopg")
    from psycopg.types.json import Jsonb

    conn = psycopg.connect(dsn, autocommit=True)
    table = f"chunks_{uuid.uuid4().hex[:8]}"
    conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
    conn.execute(f"CREATE TABLE {table} (id text PRIMARY KEY, content text, metadata jsonb, embedding vector(3))")
    with conn.cursor() as cur:
        for doc_id, text, meta, vec in DOCS:
            cur.execute(f"INSERT INTO {table} VALUES (%s, %s, %s, %s::vector)", (doc_id, text, Jsonb(meta), str(vec)))
    yield conn, table
    conn.execute(f"DROP TABLE {table}")
    conn.close()


def test_pgvector_real_server(pg_table):
    from marshal_ai.connectors.pgvector import from_pgvector

    conn, table = pg_table
    _assert_governed(from_pgvector(conn, table, embed))


def test_pgvector_metadata_values_cannot_inject_sql(pg_table):
    from marshal_ai.connectors.pgvector import from_pgvector

    conn, table = pg_table
    retriever = from_pgvector(conn, table, embed)
    hostile = "hr' OR '1'='1"
    assert retriever("q", 10, filter={"group": {"$in": [hostile]}}) == []  # matched as a literal, nothing leaks
    assert conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == len(DOCS)


def test_pgvector_rejects_invalid_identifiers():
    pytest.importorskip("psycopg")
    from marshal_ai.connectors.pgvector import from_pgvector

    with pytest.raises(ValueError):
        from_pgvector(None, "chunks; DROP TABLE users", embed)


# --- Firestore (real SDK query building) ---------------------------------------


def test_firestore_builds_a_real_filtered_vector_query(monkeypatch):
    pytest.importorskip("google.cloud.firestore")
    from google.auth.credentials import AnonymousCredentials
    from google.cloud import firestore
    from google.cloud.firestore_v1.vector_query import VectorQuery

    from marshal_ai.connectors.firestore import from_firestore

    client = firestore.Client(project="marshal-test", credentials=AnonymousCredentials())
    captured = {}

    class Snapshot:
        def __init__(self, doc_id, record):
            self.id, self._record = doc_id, record

        def to_dict(self):
            return dict(self._record)

    def fake_get(self, *args, **kwargs):
        captured["proto"] = self._to_protobuf()
        group_filter = captured["proto"].where.field_filter
        allowed = set(group_filter.value.array_value.values[i].string_value
                      for i in range(len(group_filter.value.array_value.values))) or {group_filter.value.string_value}
        return [
            Snapshot(doc_id, {"text": text, "metadata": meta, "embedding": vec, "_marshal_distance": 0.1})
            for doc_id, text, meta, vec in DOCS if meta["group"] in allowed
        ]

    monkeypatch.setattr(VectorQuery, "get", fake_get)
    _assert_governed(from_firestore(client.collection("kb"), embed))

    proto = captured["proto"]
    assert proto.where.field_filter.field.field_path == "metadata.group"
    assert proto.find_nearest.vector_field.field_path == "embedding"
    assert proto.find_nearest.distance_measure.name == "COSINE"
    assert proto.find_nearest.limit == 1


def test_firestore_skips_pushdown_past_the_in_limit(monkeypatch):
    pytest.importorskip("google.cloud.firestore")
    from google.auth.credentials import AnonymousCredentials
    from google.cloud import firestore
    from google.cloud.firestore_v1.vector_query import VectorQuery

    from marshal_ai.connectors.firestore import from_firestore

    captured = {}
    monkeypatch.setattr(VectorQuery, "get", lambda self, *a, **k: captured.setdefault("proto", self._to_protobuf()) and [])
    client = firestore.Client(project="marshal-test", credentials=AnonymousCredentials())
    from_firestore(client.collection("kb"), embed)("q", 3, filter={"group": {"$in": [f"g{i}" for i in range(31)]}})
    assert "where" not in captured["proto"]  # post-filtered by RetrievalGuard instead


# --- Pinecone / Elasticsearch / Weaviate (recording fakes) ----------------------


def test_pinecone_request_and_mapping():
    from marshal_ai.connectors.pinecone import from_pinecone

    class Index:
        def query(self, **kwargs):
            self.kwargs = kwargs
            return {"matches": [{"id": "hr-1", "score": 0.99, "metadata": {"text": "salary bands", "group": "hr"}}]}

    index = Index()
    docs = from_pinecone(index, embed, namespace="tenant-a")("q", 3, filter={"group": {"$in": ["hr"]}})
    assert index.kwargs == {"vector": [1.0, 0.0, 0.0], "top_k": 3, "include_metadata": True,
                            "namespace": "tenant-a", "filter": {"group": {"$in": ["hr"]}}}
    assert docs[0].content == "salary bands" and docs[0].metadata == {"group": "hr"}


def test_elasticsearch_request_and_mapping():
    from marshal_ai.connectors.elasticsearch import from_elasticsearch

    class Client:
        def search(self, **kwargs):
            self.kwargs = kwargs
            return {"hits": {"hits": [{"_id": "hr-1", "_score": 1.2,
                                        "_source": {"text": "salary bands", "metadata": {"group": "hr"}}}]}}

    client = Client()
    docs = from_elasticsearch(client, "kb", embed, keyword_suffix=".keyword")("q", 2, filter={"group": "hr"})
    assert client.kwargs["knn"]["filter"] == [{"term": {"metadata.group.keyword": "hr"}}]
    assert client.kwargs["knn"]["num_candidates"] == 20 and client.kwargs["source_excludes"] == ["embedding"]
    assert docs[0].metadata == {"group": "hr"} and docs[0].score == 1.2


def test_weaviate_request_and_mapping():
    pytest.importorskip("weaviate")
    from marshal_ai.connectors.weaviate import from_weaviate

    class Obj:
        uuid = "4b0c..."
        properties = {"text": "salary bands", "group": "hr"}
        metadata = type("M", (), {"distance": 0.02})()

    class Query:
        def near_vector(self, **kwargs):
            self.kwargs = kwargs
            return type("R", (), {"objects": [Obj()]})()

    collection = type("C", (), {"query": Query()})()
    docs = from_weaviate(collection, embed)("q", 2, filter={"group": {"$in": ["hr", "eng"]}})
    assert collection.query.kwargs["filters"] is not None and collection.query.kwargs["limit"] == 2
    assert docs[0].metadata == {"group": "hr"} and docs[0].score == 0.02


def test_untranslatable_filters_fall_back_to_post_filtering():
    from marshal_ai.connectors.pinecone import from_pinecone

    class Index:
        def query(self, **kwargs):
            self.kwargs = kwargs
            return {"matches": []}

    index = Index()
    from_pinecone(index, embed)("q", 2, filter={"group": {"$regex": ".*"}})
    assert "filter" not in index.kwargs


# --- LanceDB (real, embedded) ----------------------------------------------------


def test_lancedb_real_embedded(tmp_path):
    lancedb = pytest.importorskip("lancedb")
    from marshal_ai.connectors.lancedb import from_lancedb

    db = lancedb.connect(str(tmp_path / "kb.lance"))
    table = db.create_table("chunks", data=[
        {"id": doc_id, "text": text, "vector": vec, "metadata": {"group": meta["group"]}}
        for doc_id, text, meta, vec in DOCS
    ])
    _assert_governed(from_lancedb(table, embed))


def test_lancedb_string_values_cannot_break_out_of_the_sql_literal(tmp_path):
    lancedb = pytest.importorskip("lancedb")
    from marshal_ai.connectors.lancedb import from_lancedb, to_sql
    from marshal_ai.connectors._filters import parse_filter

    assert to_sql(parse_filter({"group": "x' OR '1'='1"}), "metadata") == "`metadata`.`group` = 'x'' OR ''1''=''1'"
    db = lancedb.connect(str(tmp_path / "kb.lance"))
    table = db.create_table("chunks", data=[
        {"id": doc_id, "text": text, "vector": vec, "metadata": {"group": meta["group"]}}
        for doc_id, text, meta, vec in DOCS
    ])
    assert from_lancedb(table, embed)("q", 10, filter={"group": "hr' OR '1'='1"}) == []
