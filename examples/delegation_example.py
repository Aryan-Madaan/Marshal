"""An agent acting on behalf of a user: who did it, and for whom?

`Principal(id=..., on_behalf_of=...)` splits the actor (the agent that
actually makes the call) from the subject (whose authority it exercises),
the same actor/subject split OAuth token exchange (RFC 8693) uses. Every
audit entry records both, and `DelegatedPolicy` enforces the rule that
closes the confused-deputy gap: the agent may only see what *both* it and
the user it's acting for may see.

Three scenes:
  1. The support bot on its own sees internal runbooks (it's staff tooling).
  2. The same bot acting for a customer sees only what that customer may.
  3. "What was done for alice?" — one query across every surface, even
     though alice never called anything herself.

Run: python examples/delegation_example.py
"""

from marshal_ai import (
    AttributePolicy,
    DelegatedPolicy,
    Document,
    InMemoryAuditSink,
    Principal,
    RetrievalGuard,
    ToolGuard,
)

sink = InMemoryAuditSink()
DOCS = [
    Document("faq-returns", "Returns are free within 30 days.", {"acl": ["role:customer", "role:support"]}),
    Document("runbook-refunds", "Refund override code: use ticket queue 7.", {"acl": ["role:support"]}),
    Document("order-alice-42", "Order 42: shipped Tuesday.", {"acl": ["user:alice", "role:support"]}),
]
retrieval = RetrievalGuard(lambda q, k: DOCS, policy=DelegatedPolicy(AttributePolicy(default="deny")), audit_sink=sink)
lookup = ToolGuard(tool=lambda order_id: "shipped", audit_sink=sink, tool_name="lookup_order")

bot = Principal("support-bot", {"role:support"})
alice = Principal("alice", {"role:customer", "user:alice"})
bob = Principal("bob", {"role:customer", "user:bob"})

print("=== 1. the bot on its own ===")
print([d.id for d in retrieval.retrieve("refunds", bot)])

print("\n=== 2. the bot acting for alice, then for bob ===")
for_alice = bot.acting_for(alice)
print("for alice:", [d.id for d in retrieval.retrieve("refunds", for_alice)])
print("for bob:  ", [d.id for d in retrieval.retrieve("refunds", bot.acting_for(bob))])
lookup.call(for_alice, {"order_id": "42"})

for_bob_entry = sink.query(on_behalf_of="bob")[0]
print("why bob didn't get alice's order:", for_bob_entry.denied_reasons["order-alice-42"])

print("\n=== 3. everything done for alice, across every surface ===")
for entry in sink.query(on_behalf_of="alice"):
    data = entry.to_dict()
    print(f"  [{data['kind']}] actor={entry.principal_id} for={data['on_behalf_of']}")
