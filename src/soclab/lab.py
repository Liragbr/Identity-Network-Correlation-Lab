"""Controlled localhost traffic and server-side network/auth telemetry.

All listeners bind 127.0.0.1 and all clients use 127/8. Never accepts a target
argument; no real LDAP, NTLM, Active Directory, credentials, or enterprise logs.
"""
from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .dnswire import make_query, make_response, parse_query, validate_response
from .telemetry import AuditSink

SERVER_IP = "127.0.0.1"
SUSPECT = "127.0.0.2"
BENIGN = "127.0.0.3"
MISCONFIG = "127.0.0.4"

# Deliberately fictional, fixed lab credentials. Nothing is stored in the logs.
ACCOUNTS = {f"lab.user{i:02d}": "LabOnly!2026" for i in range(1, 11)}
ACCOUNTS["lab.operator"] = "LocalDemo!2026"


class IdentityHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    sink: AuditSink

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/auth":
            self._respond(404, {"status": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 1024:
                self._respond(400, {"status": "invalid_request"})
                return
            obj = json.loads(self.rfile.read(length))
            principal = obj["principal"]
            secret = obj["password"]
            if not isinstance(principal, str) or not isinstance(secret, str) or len(principal) > 80:
                raise ValueError("invalid principal or password")
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            self._respond(400, {"status": "invalid_request"})
            return
        expected = ACCOUNTS.get(principal, "not-a-real-account")
        ok = bool(principal in ACCOUNTS and hmac.compare_digest(
            hashlib.sha256(expected.encode()).digest(), hashlib.sha256(secret.encode()).digest()
        ))
        self.sink.record(event_type="auth", src_ip=self.client_address[0], service="identity-gateway",
                         result="success" if ok else "denied", principal=principal,
                         http_status=200 if ok else 401)
        self._respond(200 if ok else 401, {"status": "success" if ok else "denied"})

    def _respond(self, status: int, body: dict[str, str]) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args: Any) -> None:
        return  # avoid logging client requests, especially credentials


class UDPResponder(threading.Thread):
    def __init__(self, sink: AuditSink) -> None:
        super().__init__(daemon=True)
        self.sink = sink
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((SERVER_IP, 0))
        self.sock.settimeout(0.15)
        self.port = self.sock.getsockname()[1]
        self.stop_event = threading.Event()

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                data, remote = self.sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                _, name, _ = parse_query(data)
                if not name.endswith(".in-addr.arpa."):
                    continue
                self.sink.record(event_type="dns_ptr", src_ip=remote[0], service="dns-ptr-lab",
                                 result="answered", qname=name)
                self.sock.sendto(make_response(data), remote)
            except (ValueError, UnicodeError, OSError):
                continue

    def close(self) -> None:
        self.stop_event.set()
        self.sock.close()
        self.join(timeout=2)


class TCPService(threading.Thread):
    def __init__(self, sink: AuditSink, service: str) -> None:
        super().__init__(daemon=True)
        self.sink = sink
        self.service = service
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((SERVER_IP, 0))
        self.sock.listen(8)
        self.sock.settimeout(0.15)
        self.port = self.sock.getsockname()[1]
        self.stop_event = threading.Event()

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                conn, remote = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                self.sink.record(event_type="tcp_connection", src_ip=remote[0],
                                 service=self.service, result="accepted", dst_port=self.port)
                conn.sendall(b"SOC-LAB READY\n")

    def close(self) -> None:
        self.stop_event.set()
        self.sock.close()
        self.join(timeout=2)


def _login(source: str, port: int, principal: str, password: str) -> int:
    conn = http.client.HTTPConnection(SERVER_IP, port, timeout=3, source_address=(source, 0))
    try:
        conn.request("POST", "/auth", body=json.dumps({"principal": principal, "password": password}),
                     headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        response.read()
        return response.status
    finally:
        conn.close()


def _dns_ptr(source: str, port: int, n: int) -> None:
    qname = f"{n}.2.0.192.in-addr.arpa."  # RFC 5737 TEST-NET-1 reverse name
    txid = 500 + n
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((source, 0))
        sock.settimeout(2)
        sock.sendto(make_query(txid, qname), (SERVER_IP, port))
        response, _ = sock.recvfrom(512)
        validate_response(response, txid)


def _connect_service(source: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((source, 0))
        sock.settimeout(3)
        sock.connect((SERVER_IP, port))
        if not sock.recv(256).startswith(b"SOC-LAB"):
            raise RuntimeError("unexpected local service response")


def run_local_experiment(destination: Path) -> list[dict[str, Any]]:
    """Perform and observe actual loopback transactions (Linux/WSL2)."""
    sink = AuditSink()

    class Handler(IdentityHandler):
        pass

    Handler.sink = sink
    server = ThreadingHTTPServer((SERVER_IP, 0), Handler)
    server.daemon_threads = True
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    dns = UDPResponder(sink)
    services = [TCPService(sink, f"inventory-service-{i}") for i in range(4)]
    try:
        server_thread.start()
        dns.start()
        for item in services:
            item.start()
        port = server.server_address[1]
        # Control: successful authorized login and a small number of PTR queries.
        assert _login(BENIGN, port, "lab.operator", "LocalDemo!2026") == 200
        _dns_ptr(BENIGN, dns.port, 10)
        _dns_ptr(BENIGN, dns.port, 11)
        # Negative control: noisy failing service credential, only ONE principal.
        for _ in range(8):
            assert _login(MISCONFIG, port, "lab.user01", "BadServicePassword") == 401
        # Investigated source: low-volume failures distributed across identities.
        for i in range(1, 9):
            assert _login(SUSPECT, port, f"lab.user{i:02d}", "LabWrong!2026") == 401
        # Real DNS PTR requests and completed TCP connects, all inside loopback.
        for i in range(21, 28):
            _dns_ptr(SUSPECT, dns.port, i)
        for item in services:
            _connect_service(SUSPECT, item.port)
        # A successful login from ANOTHER source must never attach to the suspect.
        assert _login(BENIGN, port, "lab.user05", "LabOnly!2026") == 200
        events = sink.snapshot()
        if len(events) != 31:
            raise RuntimeError(f"unexpected event count: {len(events)}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        sink.save(destination)
        return events
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=3)
        dns.close()
        for item in services:
            item.close()
