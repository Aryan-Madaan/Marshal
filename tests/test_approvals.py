import asyncio
import subprocess
import sys
import threading
import time

import pytest

from marshal_ai import InMemoryAuditSink, Principal, RiskTierPolicy, ToolCallDenied, ToolGuard
from marshal_ai.approvals import ApprovalQueue, QueuedApprovalHandler, wait_for_decision
from marshal_ai.tools import ApprovalPending

POLICY = RiskTierPolicy({"medium": "require_approval"})
AGENT = Principal("billing-agent", on_behalf_of=Principal("customer-7"))


def _setup(tmp_path, ttl=900.0, wait=0.0):
    queue = ApprovalQueue(tmp_path / "approvals.db", ttl_seconds=ttl)
    sink = InMemoryAuditSink()
    ran = []
    guard = ToolGuard(
        tool=lambda **kw: ran.append(kw) or "refunded",
        policy=POLICY,
        audit_sink=sink,
        approval_handler=QueuedApprovalHandler(queue, wait_seconds=wait, poll_seconds=0.01),
        tool_name="issue_refund",
    )
    return queue, sink, ran, guard


def test_pending_then_approved_then_runs_once(tmp_path):
    queue, sink, ran, guard = _setup(tmp_path)
    args = {"order_id": "42", "amount": 500}

    with pytest.raises(ApprovalPending) as first:
        guard.call(AGENT, args, risk_tier="medium")
    assert ran == [] and sink.tail(1)[0].outcome == "pending_approval"

    # retrying before a decision doesn't create a second request
    with pytest.raises(ApprovalPending) as second:
        guard.call(AGENT, args, risk_tier="medium")
    assert first.value.approval_id == second.value.approval_id
    assert len(queue.pending()) == 1

    queue.approve(first.value.approval_id, approver="maria@company")
    assert guard.call(AGENT, args, risk_tier="medium") == "refunded"
    entry = sink.tail(1)[0]
    assert entry.outcome == "approved" and entry.approved_by == "maria@company"

    # single use: the same approval can't release the call twice
    with pytest.raises(ApprovalPending):
        guard.call(AGENT, args, risk_tier="medium")
    assert len(ran) == 1


def test_approval_is_bound_to_the_exact_arguments(tmp_path):
    queue, _, ran, guard = _setup(tmp_path)
    with pytest.raises(ApprovalPending) as pending:
        guard.call(AGENT, {"order_id": "42", "amount": 5}, risk_tier="medium")
    queue.approve(pending.value.approval_id, approver="maria@company")

    with pytest.raises(ApprovalPending):  # $5000 is a different call
        guard.call(AGENT, {"order_id": "42", "amount": 5000}, risk_tier="medium")
    with pytest.raises(ApprovalPending):  # same args for a different customer too
        guard.call(Principal("billing-agent", on_behalf_of=Principal("customer-8")),
                   {"order_id": "42", "amount": 5}, risk_tier="medium")
    assert ran == []
    assert guard.call(AGENT, {"order_id": "42", "amount": 5}, risk_tier="medium") == "refunded"


def test_reviewer_sees_only_redacted_arguments_and_raw_values_are_never_stored(tmp_path):
    from marshal_ai import ArgumentRedaction, RedactingToolPolicy

    queue = ApprovalQueue(tmp_path / "q.db")
    guard = ToolGuard(
        tool=lambda **kw: 1,
        policy=RedactingToolPolicy(POLICY, [ArgumentRedaction("card_number", requires_attribute="role:pci")]),
        approval_handler=QueuedApprovalHandler(queue),
        tool_name="charge",
    )
    with pytest.raises(ApprovalPending):
        guard.call(AGENT, {"card_number": "4111111111111111", "amount": 9}, risk_tier="medium")
    assert queue.pending()[0].redacted_arguments == {"card_number": "[REDACTED]", "amount": 9}
    queue.close()
    assert b"4111111111111111" not in (tmp_path / "q.db").read_bytes()


def test_declined_is_a_denial_and_retries_within_the_window_are_not_re_asked(tmp_path):
    queue, sink, ran, guard = _setup(tmp_path)
    with pytest.raises(ApprovalPending) as pending:
        guard.call(AGENT, {"order_id": "1", "amount": 1}, risk_tier="medium")
    queue.decline(pending.value.approval_id, approver="maria@company", note="not eligible")

    with pytest.raises(ToolCallDenied, match="approval declined"):
        guard.call(AGENT, {"order_id": "1", "amount": 1}, risk_tier="medium")
    assert queue.pending() == [] and ran == []


def test_unanswered_requests_and_unused_approvals_expire(tmp_path):
    queue, _, ran, guard = _setup(tmp_path, ttl=0.2)
    with pytest.raises(ApprovalPending) as pending:
        guard.call(AGENT, {"order_id": "9", "amount": 1}, risk_tier="medium")
    queue.approve(pending.value.approval_id, approver="maria@company")
    time.sleep(0.3)
    assert queue.get(pending.value.approval_id).status == "expired"
    with pytest.raises(ApprovalPending):  # a stale approval doesn't release the call
        guard.call(AGENT, {"order_id": "9", "amount": 1}, risk_tier="medium")
    assert ran == []


def test_deciding_twice_or_without_an_approver_is_refused(tmp_path):
    queue, _, _, guard = _setup(tmp_path)
    with pytest.raises(ApprovalPending) as pending:
        guard.call(AGENT, {"order_id": "3", "amount": 1}, risk_tier="medium")
    with pytest.raises(ValueError):
        queue.approve(pending.value.approval_id, approver="")
    queue.approve(pending.value.approval_id, approver="maria@company")
    with pytest.raises(ValueError, match="not pending"):
        queue.decline(pending.value.approval_id, approver="eve@company")


def test_concurrent_retries_spend_one_approval_once(tmp_path):
    queue, _, ran, guard = _setup(tmp_path)
    args = {"order_id": "77", "amount": 10}
    with pytest.raises(ApprovalPending) as pending:
        guard.call(AGENT, args, risk_tier="medium")
    queue.approve(pending.value.approval_id, approver="maria@company")

    results = []

    def attempt():
        try:
            results.append(guard.call(AGENT, dict(args), risk_tier="medium"))
        except ApprovalPending:
            results.append("pending")

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count("refunded") == 1 and len(ran) == 1


def test_a_reviewer_in_another_process_can_approve(tmp_path):
    queue, _, _, guard = _setup(tmp_path)
    args = {"order_id": "5", "amount": 20}
    with pytest.raises(ApprovalPending) as pending:
        guard.call(AGENT, args, risk_tier="medium")
    script = (
        "import sys; from marshal_ai.approvals import ApprovalQueue; "
        "ApprovalQueue(sys.argv[1]).approve(sys.argv[2], approver='remote-reviewer')"
    )
    subprocess.run([sys.executable, "-c", script, str(tmp_path / "approvals.db"), pending.value.approval_id], check=True)
    assert guard.call(AGENT, args, risk_tier="medium") == "refunded"


def test_blocking_mode_waits_for_a_decision(tmp_path):
    queue, _, _, guard = _setup(tmp_path, wait=5.0)

    def reviewer():
        while not queue.pending():
            time.sleep(0.01)
        queue.approve(queue.pending()[0].id, approver="maria@company")

    threading.Thread(target=reviewer).start()
    assert guard.call(AGENT, {"order_id": "8", "amount": 1}, risk_tier="medium") == "refunded"


def test_async_wait_helper(tmp_path):
    queue, _, _, guard = _setup(tmp_path)
    with pytest.raises(ApprovalPending) as pending:
        guard.call(AGENT, {"order_id": "6", "amount": 1}, risk_tier="medium")

    async def run():
        async def approve_soon():
            await asyncio.sleep(0.05)
            queue.approve(pending.value.approval_id, approver="maria@company")

        waiter = asyncio.create_task(wait_for_decision(queue, pending.value.approval_id, timeout=5, poll_seconds=0.01))
        await approve_soon()
        return await waiter

    assert asyncio.run(run()) == "approved"


def test_pending_approval_is_counted_in_activity_reports(tmp_path):
    from marshal_ai import article12_activity_record

    _, sink, _, guard = _setup(tmp_path)
    with pytest.raises(ApprovalPending):
        guard.call(AGENT, {"order_id": "1", "amount": 1}, risk_tier="medium")
    record = article12_activity_record(sink)
    assert record.totals.approval_required == 1
