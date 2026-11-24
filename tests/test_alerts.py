import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from marshal_ai import InMemoryAuditSink, Principal, ToolGuard
from marshal_ai.alerts import (
    Alert,
    AlertManager,
    CallableNotifier,
    WebhookNotifier,
    alerts_from,
    slack_payload,
    verify_webhook_signature,
)
from marshal_ai.cli import main as cli_main
from marshal_ai.egress import EgressAllowlist

SECRET = b"0123456789abcdef-test-secret"


class Clock:
    def __init__(self, t: float = 1_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def _alert(key="health:tool:x", severity="warning"):
    return Alert(key, severity, f"{key} is bad", "because", "health")


def _manager(tmp_path, notifiers, clock=None, **kw):
    return AlertManager(tmp_path / "alerts.db", notifiers=notifiers, audit_sink=kw.pop("sink", None),
                        clock=clock or Clock(), **kw)


def test_dedup_reminder_resolve(tmp_path):
    got, clock = [], Clock()
    m = _manager(tmp_path, [CallableNotifier(got.append)], clock=clock, renotify_seconds=600)
    assert m.process([_alert()]).opened == ["health:tool:x"]
    for _ in range(5):  # still true, inside the re-notify window: silent
        clock.t += 60
        m.process([_alert()])
    assert [n.event for n in got] == ["opened"]
    clock.t += 600
    assert m.process([_alert()]).reminded == ["health:tool:x"]
    assert m.process([]).resolved == ["health:tool:x"]
    assert [n.event for n in got] == ["opened", "reminder", "resolved"]
    assert m.alerts() == [] and m.alerts(include_resolved=True)[0].state == "resolved"
    assert m.process([_alert()]).opened == ["health:tool:x"]  # recurrence is a new incident


def test_ack_silences_reminders_but_escalation_reopens(tmp_path):
    got, clock, sink = [], Clock(), InMemoryAuditSink()
    m = _manager(tmp_path, [CallableNotifier(got.append)], clock=clock, renotify_seconds=60, sink=sink)
    m.process([_alert()])
    m.acknowledge("health:tool:x", by="oncall", reason="looking")
    clock.t += 3600
    m.process([_alert()])
    assert [n.event for n in got] == ["opened"]
    m.process([_alert(severity="critical")])
    assert [n.event for n in got] == ["opened", "escalated"]
    assert m.alerts()[0].state == "open" and m.alerts()[0].acknowledged_by is None
    actions = [e.action for e in sink.all_entries()]
    assert actions == ["opened", "acknowledged", "escalated"]
    with pytest.raises(ValueError):
        m.acknowledge("health:tool:x", by="", reason="x")
    with pytest.raises(KeyError):
        m.acknowledge("nope", by="a", reason="b")


def test_failed_delivery_retries_with_backoff_then_dead_letters(tmp_path):
    clock, sink, calls = Clock(), InMemoryAuditSink(), []

    def flaky(notice):
        calls.append(notice.delivery_id)
        raise ConnectionError("https://hooks.example/?token=SECRET unreachable")

    m = _manager(tmp_path, [CallableNotifier(flaky, name="pager")], clock=clock, max_attempts=3,
                 backoff_seconds=10, sink=sink)
    r = m.process([_alert()])
    assert (r.delivered, r.retrying, r.dead_lettered) == (0, 1, 0)
    assert m.deliver() == (0, 0, 0)  # not due yet
    clock.t += 10
    assert m.deliver() == (0, 1, 0)
    clock.t += 19
    assert m.deliver() == (0, 0, 0)  # second backoff is 20s
    clock.t += 1
    assert m.deliver() == (0, 0, 1)
    assert len(set(calls)) == 1 and len(calls) == 3  # same delivery id every attempt
    dead = m.dead_letters()
    assert dead[0]["last_error"] == "ConnectionError" and "SECRET" not in json.dumps(dead)
    assert sink.all_entries()[-1].action == "dead_letter"


def test_at_least_once_a_crash_after_lease_is_redelivered(tmp_path):
    clock, got = Clock(), []
    first = _manager(tmp_path, [CallableNotifier(lambda n: (_ for _ in ()).throw(KeyboardInterrupt))], clock=clock)
    first.process([_alert()], deliver=False)
    with pytest.raises(KeyboardInterrupt):  # "crash" mid-send: row stays leased, not delivered
        first.deliver()
    second = _manager(tmp_path, [CallableNotifier(got.append)], clock=clock, lease_seconds=60)
    assert second.deliver() == (0, 0, 0)  # leased by the crashed worker
    clock.t += 61
    assert second.deliver() == (1, 0, 0) and got[0].event == "opened"
    assert second.pending() == 0


def test_each_notifier_gets_its_own_row(tmp_path):
    a, b = [], []
    m = _manager(tmp_path, [CallableNotifier(a.append, "a"), CallableNotifier(b.append, "b")])
    m.process([_alert()])
    assert len(a) == len(b) == 1 and a[0].delivery_id != b[0].delivery_id
    with pytest.raises(ValueError):
        _manager(tmp_path, [CallableNotifier(a.append, "x"), CallableNotifier(b.append, "x")])


def test_alerts_from_health_and_signals_carry_no_identities():
    sink = InMemoryAuditSink()

    def broken():
        raise TimeoutError

    guard = ToolGuard(tool=broken, audit_sink=sink, tool_name="carrier", audit_outcomes=True)
    for _ in range(6):
        with pytest.raises(TimeoutError):
            guard.call(Principal("alice@corp.example"), {})
    alerts = alerts_from(sink)
    tool = next(a for a in alerts if a.key == "health:tool:carrier")
    assert tool.severity == "critical"
    assert all("alice@corp.example" not in a.detail for a in alerts if a.source == "signal")


# --- webhook ---------------------------------------------------------------------


class _Receiver(BaseHTTPRequestHandler):
    received: list = []
    status = 204
    location = None

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        type(self).received.append((dict(self.headers), body))
        self.send_response(self.status)
        if self.location:
            self.send_header("Location", self.location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def receiver():
    _Receiver.received, _Receiver.status, _Receiver.location = [], 204, None
    server = HTTPServer(("127.0.0.1", 0), _Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/hook"
    server.shutdown()


def test_webhook_signs_and_receiver_verifies(tmp_path, receiver):
    m = _manager(tmp_path, [WebhookNotifier(receiver, secret=SECRET, allow_http=True)])
    assert m.process([_alert()]).delivered == 1
    headers, body = _Receiver.received[0]
    assert verify_webhook_signature(SECRET, body, headers["Marshal-Signature"])
    assert not verify_webhook_signature(SECRET, body + b" ", headers["Marshal-Signature"])
    assert not verify_webhook_signature(b"another-secret-of-16b", body, headers["Marshal-Signature"])
    assert not verify_webhook_signature(SECRET, body, headers["Marshal-Signature"], now=10**10)  # replay
    assert json.loads(body)["delivery_id"] == headers["Marshal-Delivery-Id"]


def test_webhook_refuses_redirects_and_errors(tmp_path, receiver):
    _Receiver.status, _Receiver.location = 302, "http://169.254.169.254/latest/meta-data"
    m = _manager(tmp_path, [WebhookNotifier(receiver, allow_http=True)])
    r = m.process([_alert()])
    assert (r.delivered, r.retrying) == (0, 1) and len(_Receiver.received) == 1


def test_webhook_url_validation():
    with pytest.raises(ValueError, match="https"):
        WebhookNotifier("http://hooks.example/x")
    with pytest.raises(ValueError, match="credentials"):
        WebhookNotifier("https://user:pw@hooks.example/x")
    with pytest.raises(ValueError, match="allowlist"):
        WebhookNotifier("https://evil.example/x", allowlist=EgressAllowlist(["hooks.ourcompany.example"]))
    with pytest.raises(ValueError, match="16 bytes"):
        WebhookNotifier("https://hooks.example/x", secret=b"short")
    WebhookNotifier("https://hooks.ourcompany.example/x", allowlist=EgressAllowlist(["*.ourcompany.example"]))


def test_slack_payload_shape():
    from marshal_ai.alerts import AlertNotice

    notice = AlertNotice("d", "opened", "k", "critical", "t", "why", "health", 0.0, 0.0)
    assert slack_payload(notice)["text"].startswith("[CRITICAL] t")


def test_cli_lists_and_acknowledges(tmp_path, capsys):
    m = _manager(tmp_path, [])
    m.process([_alert()])
    m.close()
    db = str(tmp_path / "alerts.db")
    cli_main(["alerts", "list", db])
    assert "health:tool:x" in capsys.readouterr().out
    cli_main(["alerts", "ack", db, "health:tool:x", "--as", "oncall", "--reason", "on it"])
    cli_main(["alerts", "list", db])
    assert "acked by oncall" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        cli_main(["alerts", "ack", db, "health:tool:x"])


def test_cli_ack_and_quarantine_reach_the_audit_trail(tmp_path):
    from marshal_ai.sinks import SQLiteAuditSink

    m = _manager(tmp_path, [])
    m.process([_alert()])
    m.close()
    audit = str(tmp_path / "audit.db")
    cli_main(["alerts", "ack", str(tmp_path / "alerts.db"), "health:tool:x", "--as", "oncall", "--reason", "r",
              "--audit", audit])
    cli_main(["quarantine", "add", str(tmp_path / "q.db"), "tool", "t", "--as", "oncall", "--reason", "r",
              "--audit", audit])
    kinds = [(e.to_dict()["kind"], e.principal_id) for e in SQLiteAuditSink(audit).all_entries()]
    assert kinds == [("alert", "oncall"), ("quarantine", "oncall")]
