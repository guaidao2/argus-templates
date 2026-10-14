#!/usr/bin/env python3
"""End-to-end verification for the rpcbind template.

It starts fake-rpcbind.py with a known registry, points a real argus binary at
it, and checks the report against what the template promises -- including the
negative cases, because a fingerprint that fires on the wrong answer is worse
than one that does not fire at all:

    modern : TCP 111   every disclosed program is reported, and the port's
                       banner carries the disclosed netid and universal address
    modern : no --findings
                       check rules stay silent unless the flag is given
    v2only : TCP 111   an old portmapper (PROG_MISMATCH, no RPCB) is still
                       identified, by the built-in rule, and the v3 rule does
                       not claim it
    rexd-last : TCP 111
                       a program that is the LAST entry of the registry list is
                       still reported (the entry marker may be 0)
    http : TCP 111     a port that is not RPC produces no RPC finding
    modern : UDP 111   documents the current gap: argus's UDP scan payload for
                       111 is a single 0x00 byte, the portmapper drops it, so the
                       port never reaches the detector (see README)
    modern : TCP 32771 the opt-in any-port document identifies rpcbind off 111

Usage:
    python test/verify.py --argus /path/to/argus
    python test/verify.py --argus ./argus --port 111 --verbose
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

# The mock is imported in the pattern self-test below. Do not leave a
# __pycache__ directory inside the repository when that happens.
sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_DIR = os.path.dirname(HERE)
PLUGIN_MAIN = os.path.join(PLUGIN_DIR, "rpcbind.yaml")
MOCK = os.path.join(HERE, "fake-rpcbind.py")
HOST = "127.0.0.1"

# Every match id rpcbind.yaml can report over TCP, and the UDP one.
TCP_FINDINGS = [
    "unauth-dump",
    "rexd",
    "rusersd",
    "rstatd",
    "walld",
    "sprayd",
    "bootparam",
    "keyserv",
    "amd-amq",
]
UDP_FINDINGS = ["udp-amplification"]

# The disclosed text the report should carry for the "modern" registry. The
# port banner is capped at 200 characters by argus, so only the first few
# registrations fit there: rpcbind's own entries plus their netid and owner
# strings. The NFS address (0.0.0.0.8.1 == 8*256+1 == 2049) sits further down
# the answer, so the pattern self-test below covers it instead.
MODERN_BANNER = ["0.0.0.0.0.111", "tcp", "superuser"]


def plugin_patterns(path: str) -> dict:
    """Pull "match id -> pattern" out of the plugin, so the self-test below
    checks the pattern that actually ships rather than a copy of it."""
    import re
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    out = {}
    for m in re.finditer(r"- id: ([\w-]+)\n(?:(?!- id: ).)*?pattern: '([^']+)'", text, re.S):
        out.setdefault(m.group(1), m.group(2))
    return out


def pattern_selftest() -> list[str]:
    """Check the shipped patterns against the wire bytes, not against a report.

    The scenarios prove the template works end to end. These two properties are
    the ones that would rot silently, because a report cannot show them: a v2
    (portmap) answer must not satisfy the RPCB pattern, and a v3 answer's
    universal address must decode back to the port it is describing.
    """
    import importlib.util
    import re
    import types

    spec = importlib.util.spec_from_file_location("fake_rpcbind", MOCK)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    patterns = plugin_patterns(PLUGIN_MAIN)
    failures = []
    for needed in ("rpcb-v3", "unauth-dump", "udp-amplification"):
        if needed not in patterns:
            failures.append("pattern for match %r not found in the plugin" % needed)
    if failures:
        return failures

    args = types.SimpleNamespace(bind_host="127.0.0.1", uaddr_host="0.0.0.0")

    def answer(registry, vers):
        server = mod.Server(registry, args)
        body = server.v2_dump_body() if vers == 2 else server.v3_dump_body()
        header = mod.u32(0x80000000 | len(body)) + server.reply_header(1, mod.SUCCESS) + body
        # argus matches against a latin-1 decoding of the response.
        return header, body, header.decode("latin-1"), body.decode("latin-1")

    modern = mod.registry_for("modern")
    _, _, tcp_v3, v3_body_text = answer(modern, 3)
    _, _, tcp_v2, _ = answer(modern, 2)

    if not re.search(patterns["rpcb-v3"], tcp_v3):
        failures.append("rpcb-v3 does not match a v3 answer")
    if re.search(patterns["rpcb-v3"], tcp_v2):
        failures.append("rpcb-v3 matches a v2 (portmap) answer: it would claim a "
                        "portmapper that does not speak RPCB")
    if not re.search(patterns["unauth-dump"], tcp_v2):
        failures.append("unauth-dump does not match a v2 answer with a registry")

    # Over UDP there is no record marker, so the datagram starts at the xid.
    udp_server = mod.Server(modern, args)
    udp_body = udp_server.v2_dump_body()
    udp_v2 = (udp_server.reply_header(1, mod.SUCCESS) + udp_body).decode("latin-1")
    if not re.search(patterns["udp-amplification"], udp_v2):
        failures.append("udp-amplification does not match a v2 answer over UDP")

    # An empty registry is not a disclosure: the list must have an entry.
    empty = mod.Server(mod.Registry([], supports_v3=True), args)
    empty_tcp = (mod.u32(0x80000000 | len(empty.v2_dump_body()))
                 + empty.reply_header(1, mod.SUCCESS) + empty.v2_dump_body()).decode("latin-1")
    if re.search(patterns["unauth-dump"], empty_tcp):
        failures.append("unauth-dump fires on an empty registry")

    # An old portmapper answers PROG_MISMATCH, which must not be read as RPCB.
    old = mod.registry_for("v2only")
    mismatch = (mod.u32(0x80000000 | 8) + mod.Server(old, args).reply_header(1, mod.PROG_MISMATCH)
                + mod.u32(2) + mod.u32(2)).decode("latin-1")
    if re.search(patterns["rpcb-v3"], mismatch):
        failures.append("rpcb-v3 matches a PROG_MISMATCH reply")

    # The universal address carries the port; decode NFS and compare.
    nfs_port = next(port for prog, _, netid, port, _ in modern.entries
                    if prog == 100003 and netid == "tcp")
    want = mod.universal_address("0.0.0.0", nfs_port)
    if want not in v3_body_text:
        failures.append("the v3 answer does not carry %s" % want)
    else:
        host, p1, p2 = want.rsplit(".", 2)
        if int(p1) * 256 + int(p2) != nfs_port:
            failures.append("%s does not decode back to port %d" % (want, nfs_port))
    return failures


def scenarios(port: int) -> list[dict]:
    high = 32771
    return [
        {
            "name": "modern : tcp/%d : template" % port,
            "profile": "modern",
            "port": port,
            "proto": "tcp",
            "plugin": PLUGIN_MAIN,
            "args": ["-Pn", "-sV", "--findings"],
            "expect": {
                "service": "rpcbind",
                "method": "probed",
                "product": "ONC RPC portmapper",
                "extrainfo_contains": "RPCB v3",
                "cpe_contains": "rpcbind_project",
                "banner_contains": MODERN_BANNER,
                "findings_present": TCP_FINDINGS,
                "findings_absent": UDP_FINDINGS,
            },
            "log_must_not_contain": ["record marker=more-fragments length=0"],
        },
        {
            "name": "modern : tcp/%d : checks are opt-in" % port,
            "profile": "modern",
            "port": port,
            "proto": "tcp",
            "plugin": PLUGIN_MAIN,
            "args": ["-Pn", "-sV"],  # no --findings
            "expect": {
                "service": "rpcbind",
                "method": "probed",
                "findings_present": [],
                "findings_absent": TCP_FINDINGS + UDP_FINDINGS,
            },
        },
        {
            "name": "v2only : tcp/%d : old portmap" % port,
            "profile": "v2only",
            "port": port,
            "proto": "tcp",
            "plugin": PLUGIN_MAIN,
            "args": ["-Pn", "-sV", "--findings"],
            "expect": {
                # The v3 rule does not fire (PROG_MISMATCH) and the built-in
                # rule identifies the port instead: same service, no RPCB info.
                "service": "rpcbind",
                "method": "probed",
                "extrainfo_not_contains": "RPCB v3",
                "findings_present": ["unauth-dump"],
                "findings_absent": ["rexd", "rusersd", "rstatd", "walld", "sprayd",
                                    "bootparam", "keyserv", "amd-amq"] + UDP_FINDINGS,
            },
            "log_must_contain": ["PROG_MISMATCH"],
        },
        {
            "name": "rexd-last : tcp/%d : last list entry" % port,
            "profile": "rexd-last",
            "port": port,
            "proto": "tcp",
            "plugin": PLUGIN_MAIN,
            "args": ["-Pn", "-sV", "--findings"],
            "expect": {
                "service": "rpcbind",
                "method": "probed",
                "findings_present": ["unauth-dump", "rexd"],
                "findings_absent": ["rusersd", "rstatd", "walld", "sprayd",
                                    "bootparam", "keyserv", "amd-amq"] + UDP_FINDINGS,
            },
        },
        {
            "name": "http : tcp/%d : not RPC at all" % port,
            "profile": "http",
            "port": port,
            "proto": "tcp",
            "plugin": PLUGIN_MAIN,
            "args": ["-Pn", "-sV", "--findings"],
            "expect": {
                "service": "http",
                "method": "probed",
                "extrainfo_not_contains": "RPCB",
                "findings_present": [],
                "findings_absent": TCP_FINDINGS + UDP_FINDINGS,
            },
        },
        {
            "name": "modern : udp/%d : known gap" % port,
            "profile": "modern",
            "port": port,
            "proto": "udp",
            "plugin": PLUGIN_MAIN,
            "args": ["-Pn", "-sV", "--findings", "-sU"],
            "expect": {
                # Not a template bug: argus classifies a silent UDP probe as
                # open|filtered and only runs the detector on open ports, and
                # its scan payload for 111 is a 1 byte 0x00 that a portmapper
                # drops. The UDP check therefore cannot run yet.
                "state": "open|filtered",
                "service": None,
                "findings_present": [],
                "findings_absent": UDP_FINDINGS + TCP_FINDINGS,
            },
            "log_must_contain": ["datagram dropped"],
            "gap": (
                "argus sends 0x00 as the UDP scan payload for 111; rpcbind drops "
                "datagrams it cannot decode, so udp/111 stays open|filtered and "
                "never reaches the detector. One entry in udpHexPayloads fixes "
                "this -- see README.md, 'Upstream notes'."
            ),
        },
        {
            "name": "modern : tcp/%d : built-in rules only (baseline)" % port,
            "profile": "modern",
            "port": port,
            "proto": "tcp",
            "plugin": None,  # --no-plugins: the built-in database on its own
            "args": ["-Pn", "-sV", "--findings"],
            "expect": {
                "service": "rpcbind",
                "method": "probed",
                "findings_present": ["nfs"],
                "findings_absent": TCP_FINDINGS,
            },
            # The built-in probe is a clean 44 byte call: 4 byte record marker
            # that declares 40, then 40 bytes of XDR. Nothing is left in the
            # socket, which is what this forbids.
            "log_must_not_contain": ["more-fragments", "dropped"],
        },
        {
            "name": "modern : tcp/%d : any-port document" % high,
            "profile": "modern",
            "port": high,
            "proto": "tcp",
            "plugin": PLUGIN_DIR,  # both documents, the way a pack loads
            "args": ["-Pn", "-sV", "--findings"],
            "expect": {
                "service": "rpcbind",
                "method": "probed",
                "extrainfo_contains": "RPCB v3",
                "findings_present": [],
                # The template's checks bind to port 111 and cannot follow the
                # service name today; the built-in checks can, which is the gap
                # demonstrated below.
                "findings_absent": TCP_FINDINGS + UDP_FINDINGS,
            },
            "rules_present": ["rpc-registered-services"],
            "gap": (
                "the template's checks bind to port 111 and do not follow a "
                "service identified on another port, because AddYAMLFront does "
                "not index plugin rules by service. The built-in checks do fire "
                "here, which is what makes the difference visible. See README.md, "
                "'Upstream notes'."
            ),
        },
    ]


def find_argus(explicit: str | None) -> str | None:
    if explicit:
        return explicit if os.path.exists(explicit) else None
    env = os.environ.get("ARGUS_BIN")
    if env and os.path.exists(env):
        return env
    found = shutil.which("argus")
    if found:
        return found
    for guess in ("argus", "argus.exe", os.path.join("..", "argus", "argus"),
                  os.path.join("..", "argus", "argus.exe"),
                  os.path.join("..", "argus", "dist", "argus-windows-amd64.exe")):
        if os.path.exists(guess):
            return os.path.abspath(guess)
    return None


def wait_for_port(port: int, kind: str, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM if kind == "tcp" else socket.SOCK_DGRAM)
        try:
            if kind == "tcp":
                s.settimeout(0.3)
                s.connect(("127.0.0.1", port))
                return True
            s.bind(("127.0.0.1", port))  # bound by the mock already? then free
            s.close()
            return False
        except OSError:
            time.sleep(0.1)
        finally:
            try:
                s.close()
            except OSError:
                pass
    return False


def port_in_use(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))
        return False
    except OSError as e:
        print("cannot bind 127.0.0.1:%d (%s)." % (port, e))
        print("  * on Linux, ports below 1024 need root or CAP_NET_BIND_SERVICE:")
        print("      sudo setcap cap_net_bind_service=+ep $(command -v python3)")
        print("      # or: sudo sysctl net.ipv4.ip_unprivileged_port_start=111")
        print("  * the template's checks bind to port 111, so they cannot be")
        print("    verified on another port")
        return True
    finally:
        s.close()


def run_scenario(argus: str, sc: dict, workdir: str) -> tuple[bool, list[str], str]:
    failures: list[str] = []
    log_path = os.path.join(workdir, "mock.log")
    out_json = os.path.join(workdir, "report.json")
    with open(log_path, "wb") as log:
        mock = subprocess.Popen(
            [sys.executable, MOCK, "--profile", sc["profile"],
             "--tcp-port", str(sc["port"]), "--udp-port", str(sc["port"])],
            stdout=log, stderr=subprocess.STDOUT,
        )
    try:
        if sc["profile"] != "http" and not wait_for_port(sc["port"], "tcp"):
            return False, ["mock never listened on tcp/%d" % sc["port"]], ""
        cmd = [argus, "-p", str(sc["port"]), "-oJ", out_json]
        if sc["plugin"]:
            cmd += ["--plugin-dir", sc["plugin"]]
        else:
            cmd += ["--no-plugins"]
        cmd += [HOST] + sc["args"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if not os.path.exists(out_json):
            return False, ["argus produced no JSON report (exit %d)\nstdout:\n%s\nstderr:\n%s"
                           % (proc.returncode, proc.stdout[-2000:], proc.stderr[-2000:])], ""
    finally:
        mock.terminate()
        try:
            mock.wait(timeout=5)
        except subprocess.TimeoutExpired:
            mock.kill()

    with open(out_json, encoding="utf-8") as fh:
        doc = json.load(fh)
    ports = [p for h in doc.get("hosts", []) for p in h.get("ports", [])
             if p["port"] == sc["port"] and p["protocol"] == sc["proto"]]
    if not ports:
        return False, ["no %s/%d entry in the report" % (sc["proto"], sc["port"])], ""
    entry = ports[0]
    service = entry.get("service") or {}
    findings = entry.get("findings") or []
    ids = [f.get("id") for f in findings]
    rules = [f.get("rule") for f in findings]
    exp = sc["expect"]

    if "state" in exp and entry["state"] != exp["state"]:
        failures.append("state = %r, want %r" % (entry["state"], exp["state"]))
    if "service" in exp:
        got = service.get("name")
        if exp["service"] is None and got:
            failures.append("service = %r, want none" % got)
        elif exp["service"] is not None and got != exp["service"]:
            failures.append("service = %r, want %r" % (got, exp["service"]))
    if exp.get("product") and service.get("product") != exp["product"]:
        failures.append("product = %r, want %r" % (service.get("product"), exp["product"]))
    if exp.get("method") and service.get("method") != exp["method"]:
        # "probed" means a rule matched an answer. "table" means the port was
        # only named from the port table, which is what a probe that never got a
        # reply looks like in a report: same service name, no work actually done.
        failures.append("service method = %r, want %r (a port table fallback would "
                        "hide a probe that never worked)"
                        % (service.get("method"), exp["method"]))
    if exp.get("extrainfo_contains") and exp["extrainfo_contains"] not in service.get("extrainfo", ""):
        failures.append("extrainfo = %r, want it to contain %r"
                        % (service.get("extrainfo"), exp["extrainfo_contains"]))
    if exp.get("extrainfo_not_contains") and exp["extrainfo_not_contains"] in service.get("extrainfo", ""):
        failures.append("extrainfo = %r, want it NOT to contain %r"
                        % (service.get("extrainfo"), exp["extrainfo_not_contains"]))
    if exp.get("cpe_contains") and not any(exp["cpe_contains"] in c for c in service.get("cpe", [])):
        failures.append("cpe = %r, want it to contain %r" % (service.get("cpe"), exp["cpe_contains"]))
    for want in exp.get("banner_contains", []):
        if want not in service.get("banner", ""):
            failures.append("banner %r does not contain %r" % (service.get("banner"), want))
    for want in exp.get("findings_present", []):
        if want not in ids:
            failures.append("finding %r missing (got %r)" % (want, ids))
    for unwanted in exp.get("findings_absent", []):
        if unwanted in ids:
            failures.append("finding %r should not have fired" % unwanted)
    for want in sc.get("rules_present", []):
        if want not in rules:
            failures.append("no finding from rule %r (got %r)" % (want, rules))

    log_text = ""
    if os.path.exists(log_path):
        with open(log_path, encoding="utf-8", errors="replace") as fh:
            log_text = fh.read()
    for want in sc.get("log_must_contain", []):
        if want not in log_text:
            failures.append("wire log does not contain %r" % want)
    for unwanted in sc.get("log_must_not_contain", []):
        if unwanted in log_text:
            failures.append("wire log contains %r" % unwanted)

    detail = "service=%s %s | findings=%s" % (
        service.get("name"), (service.get("extrainfo") or ""), ",".join(ids) or "-")
    return not failures, failures, detail


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--argus", help="path to the argus binary (default: $ARGUS_BIN, $PATH)")
    ap.add_argument("--port", type=int, default=111, help="port for the port 111 scenarios")
    ap.add_argument("--verbose", action="store_true", help="print each scenario's wire log")
    ap.add_argument("--only", help="run only the scenarios whose name contains this string")
    ap.add_argument("--keep", action="store_true", help="keep the temporary directories")
    args = ap.parse_args()

    argus = find_argus(args.argus)
    if not argus or not os.path.exists(argus):
        print("no argus binary found; pass --argus, e.g.")
        print("    cd argus && go build -o /tmp/argus ./cmd/argus")
        return 2
    print("argus:  %s" % argus)
    print("plugin: %s" % PLUGIN_DIR)
    print("mock:   %s" % MOCK)
    if port_in_use(args.port):
        return 2

    failed = 0

    print("\n-- pattern self-test (wire bytes, no argus involved) --")
    selftest_failures = pattern_selftest()
    print("%s pattern self-test" % ("PASS" if not selftest_failures else "FAIL"))
    for f in selftest_failures:
        print("     - %s" % f)
    if selftest_failures:
        failed += 1

    for sc in scenarios(args.port):
        if args.only and args.only not in sc["name"]:
            continue
        workdir = tempfile.mkdtemp(prefix="argus-rpcbind-")
        try:
            ok, failures, detail = run_scenario(argus, sc, workdir)
            print("\n%s %s" % ("PASS" if ok else "FAIL", sc["name"]))
            print("     %s" % detail)
            if sc.get("gap"):
                print("     note: %s" % sc["gap"])
            for f in failures:
                print("     - %s" % f)
            if args.verbose:
                with open(os.path.join(workdir, "mock.log"), encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        print("       | %s" % line.rstrip())
            if not ok:
                failed += 1
        finally:
            if args.keep:
                print("     kept: %s" % workdir)
            else:
                shutil.rmtree(workdir, ignore_errors=True)

    print("\n%d scenario(s) failed" % failed if failed else "\nall scenarios passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
