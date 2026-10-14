# rpcbind — port 111

[中文版](README.zh-CN.md)

Turns what port 111 discloses into lines in an argus report. Port 111 is one of
the few ports that answers a question you did not have to guess: ask it for its
registry and it names every RPC program the host runs. This template identifies
the port from the RPCB v3 answer, so the disclosed text lands in the report, and
then renders each registered program as its own labelled finding.

```
$ argus -Pn -sV --findings -p 111 10.0.0.9

111/tcp open  rpcbind  ONC RPC portmapper (RPCB v3, registry readable)
| check: RPC: the portmapper disclosed its registry without credentials [LOW]
| One unauthenticated DUMP call returned every RPC program this host has registered...
| check: RPC registry: rexd (program 100017) is registered [MEDIUM]
| rexd is the remote execution service behind "on" and "rex"...
|_check: RPC registry: rusersd (program 100002) is registered [LOW]
```

## What it discloses, and where it lands

| What rpcbind gives up | Where it appears | How to see it |
| --- | --- | --- |
| The registry itself: which programs are registered, with their versions and transports | One finding per program, `rule: rpcbind-registry` | `--findings` |
| Netids, universal addresses and owners (the RPCB v3 answer is XDR strings, so it renders as text) | The port's banner (`service.banner`), which `-v` prints and `-oX`/`-oJ` always keep | `-sV` |
| "This is an RPCB-capable portmapper, not an ancient portmap" | The port line: `rpcbind ONC RPC portmapper (RPCB v3, registry readable)` | `-sV` |
| That 111/udp answers unauthenticated queries | A finding, `rule: rpcbind-udp-registry` | `--findings -sU` |
| The next steps for every one of those programs | The `--hack-reason` note on the port | `--hack-reason` |

Two honest limits of that table:

* A finding's text is **static** in this plugin schema: it can name program
  `100017`, it cannot interpolate the port that program listens on. The ports
  come from the banner (the last two numbers of a universal address are the port
  in base 256, so `0.0.0.0.8.1` is 2049) and from `rpcinfo -p` for the whole
  list. argus caps the banner at 200 characters, so it carries the head of the
  registry, not all of it.
* The registry is answered by design. "You can enumerate this host" is an
  exposure statement, not a defect, which is why the finding is `low` and the
  description says so.

## Install

Requires argus **1.0.1 or newer**; the document declares it, so an older build
refuses to load it instead of quietly doing half the job.

```bash
# just this document (port 111 only) - recommended
argus --register-plugin ./rpcbind/rpcbind.yaml

# or the whole directory, which also enables the any-port document below
argus --register-plugin ./rpcbind/
```

Scanning:

```bash
argus -Pn -sV -p 111 10.0.0.9                        # identify, banner, built-in checks
argus -Pn -sV --findings -p 111 10.0.0.9             # + this template's registry rendering
argus -Pn -sV --findings -sU -p 111 10.0.0.9         # + the UDP side
argus -Pn -sV --findings --hack-reason -p 111 10.0.0.9
```

`--findings` is required for the findings, exactly as for the built-in checks:
the probes are deliberate requests, so they are opt-in.

## Coverage

| Rule | Match id | Kind | Severity | Fires when |
| --- | --- | --- | --- | --- |
| `rpcbind-rpcb-v3` | `rpcb-v3` | fingerprint | — | the port answers an RPCB v3 DUMP: identifies and shows the disclosed text |
| `rpcbind-rpcb-v3-udp` | `rpcb-v3-udp` | fingerprint (udp) | — | the same over UDP |
| `rpcbind-registry` | `unauth-dump` | check | low | a successful DUMP with a non-empty registry |
| `rpcbind-registry` | `rexd` | check | medium | program 100017 registered (remote execution) |
| `rpcbind-registry` | `rusersd` | check | low | program 100002 (logged-in users) |
| `rpcbind-registry` | `rstatd` | check | low | program 100001 (uptime, load, counters) |
| `rpcbind-registry` | `walld` | check | info | program 100008 (write to every terminal) |
| `rpcbind-registry` | `sprayd` | check | low | program 100012 (a traffic generator pointed by the client) |
| `rpcbind-registry` | `bootparam` | check | low | program 100026 (netboot parameters) |
| `rpcbind-registry` | `keyserv` | check | low | program 100029 (secure RPC keys) |
| `rpcbind-registry` | `amd-amq` | check | low | program 300019 (the automounter control interface) |
| `rpcbind-udp-registry` | `udp-amplification` | check (udp) | medium | DUMP answered over UDP |
| `rpcbind-any-port` (separate document) | `rpcb-v3` | fingerprint | — | an RPCB v3 answer on **any** open port |

Program numbers come from `/etc/rpc` / `rpc(5)`. The NFS/NIS family
(100003 nfs, 100004 ypserv, 100005 mountd, 100011 rquotad, 100021 nlockmgr,
100024 status, 100227 nfs_acl) is deliberately **not** duplicated here: the
built-in `checks-rpc` rules already report those, and two findings for the same
registration would double the noise on every rpcbind host. This template adds
the legacy SunOS-era daemons that a modern `/etc/rpc` still names and that the
built-in set does not mention.

Severities follow one rule: a registered daemon is a fact, and the severity says
how much the *service* is worth to an attacker. `rexd` executes commands with
thin authentication, so `medium`; user and host enumeration is `low`; a write-all
broadcast is `info`; the registry itself is `low` because a portmapper answering
DUMP is what a portmapper does. Nothing here is `high` or `critical`, and nothing
claims a vulnerability that was not observed: "registered" is what was measured.

## Evidence rules

Each pattern is shaped so that it can only fire on the fact it claims.

* **Success replies only.** Every pattern starts with the reply header
  `xid, REPLY, MSG_ACCEPTED, AUTH_NULL verifier, SUCCESS`, written as
  `(\x00\x00\x00\x01){2}(\x00\x00\x00\x00){4}`. An old portmap answers a v3 call
  with `PROG_MISMATCH`, which does not have `SUCCESS` there, so the RPCB rule
  cannot claim a portmapper that does not speak RPCB. The self-test in
  `test/verify.py` asserts exactly this against `PROG_MISMATCH` bytes.
* **The v3 pattern cannot match a v2 answer.** A portmap v2 answer is four byte
  words from end to end, so it contains no netid string; the RPCB pattern
  requires `prog 100000, vers 2|3|4, <length 3|4> "tcp"|"udp"`, which is a shape
  only an RPCB answer can have. The self-test feeds it both answers.
* **A registry entry is anchored to its element marker.** XDR encodes a list as
  `bool` + element per entry, ending with a zero. So each program number is
  preceded by four bytes whose first three are zero, and the last is allowed to
  be **0 as well as 1**: the last entry of the list is preceded by a zero. A
  pattern that demanded `\x00\x00\x00\x01` would go quiet on exactly the host
  whose registry ends with the program in question. The `rexd-last` scenario
  covers that.
* **An empty registry is not a disclosure.** `unauth-dump` requires the list to
  be non-empty (the "more entries follow" marker), so a portmapper with nothing
  registered does not produce a finding about disclosure. Asserted in the
  self-test.
* **A v2 answer with no reply is not a finding.** UDP has no record marking, and
  a datagram a server cannot decode gets no answer at all; an answer to the UDP
  probe therefore means a real portmapper answered DUMP, not that something
  echoed bytes back.
* **A probe is one write and one read.** Each probe carries the full 40 bytes of
  XDR its call needs, with the field layout written out in the comments, and the
  wire log in `test/verify.py` fails the run if a probe leaves stray bytes in the
  socket.

## Deliberate exclusions

* **`SET` and `UNSET` are never sent.** They change the registry, and a
  successful `UNSET` removes a live mapping from a running host. That is an
  attack, not a check. The hack-reason note says the same, and says why they are
  also restricted to the loopback transport.
* **CVE-2017-8779 (rpcbomb) is not probed.** It is a memory exhaustion reached
  through `RPCBPROC_CALLIT`, so the probe *is* the denial of service. It is also
  a version question: rpcbind through 0.2.4 and libtirpc through 1.0.1 are
  affected, and an ONC RPC server never reports its version. Read the package
  version on the host. This is written into the hack-reason note where the person
  reading the report will find it.
* **`GETPORT`/`GETADDR` lookups for specific programs are not used as checks.**
  They would duplicate the built-in NFS/NIS findings and add a second request per
  program for the same information the registry already carries.
* **No any-port checks.** The any-port document identifies the service only. It
  does not need checks of its own: the rules in `rpcbind.yaml` bind to
  `service: rpcbind` as well as to port 111, so they follow the service onto
  whatever port it was identified on, including the one this document found.
* **No inline-call probing of other RPC services.** That is a different tool's
  job, and it would mean speaking to the scanned host's *clients*.

## Verifying it

```bash
python test/verify.py --argus /path/to/argus      # or: --argus ./argus.exe
```

The harness starts `test/fake-rpcbind.py` -- a strict mock portmapper (portmap
v2 and RPCB v3, TCP record marking and UDP, malformed datagrams dropped in
silence, `PROG_MISMATCH` for an unsupported protocol version) -- and checks a
real argus report against it:

| Scenario | What it proves |
| --- | --- |
| `modern : tcp/111 : template` | every registered program is reported; the banner carries the disclosed netid, universal address and owner; `method` is `probed`, not a port-table guess |
| `checks are opt-in` | no finding at all without `--findings` |
| `v2only` | an old portmap is still identified (by the built-in rule) and the RPCB rule does not claim it |
| `rexd-last` | a program that is the **last** entry of the registry is still reported |
| `http` | a port that is not RPC produces no RPC finding |
| `udp/111 : template` | the port is open over UDP, so it is identified there too and the amplification finding fires |
| `built-in rules only` | the baseline: the built-in database identifies the port and reports the NFS family, with no stray bytes on the wire (byte counts: 44 = 4 byte marker that declares 40 + 40 bytes of call) |
| `any-port document` | rpcbind on a non-standard port is identified **and** the template's checks follow the service there |
| pattern self-test | a v2 answer, an empty registry and a `PROG_MISMATCH` reply must not satisfy the v3/`unauth-dump` patterns |

The harness needs to bind 111, because the template's checks bind to that port.
On Linux that means root or `CAP_NET_BIND_SERVICE`; if it cannot bind, it says so
instead of skipping quietly. A run against a build older than 1.0.1 says that
too, rather than reporting a wall of failures.

## Writing notes

Useful for the next template in this repository:

* In `send:`, bytes are written as YAML double-quoted escapes (`"\x80\x00..."`):
  YAML decodes them to code points, and argus turns every rune below `U+0100`
  back into one byte. In `pattern:`, use **single** quotes so the backslash
  reaches RE2 (`'\x80\x00...'`), and remember the response is matched as a
  latin-1 decoding, which is what makes `\xNN` mean *byte* NN.
* RE2 has no wildcard digits inside a `\x` escape: `\x0[2-4]` is an invalid
  escape, not a pattern. Write `[\x02-\x04]` instead.
* Name the disclosed program number in the finding **title**, since the text is
  static: "RPC registry: rexd (program 100017) is registered" reads as an
  inventory line and stays true whatever port it listens on.

## References

* RFC 1833, the rpcbind protocol (RPCB v2/v3/v4, procedures, universal
  addresses): <https://www.rfc-editor.org/rfc/rfc1833.html>
* RFC 1057, the portmap v2 protocol: <https://www.rfc-editor.org/rfc/rfc1057.html>
* `rpc(5)`, the program number table used above:
  <https://man7.org/linux/man-pages/man5/rpc.5.html>
* US-CERT TA14-017A, UDP based amplification attacks (portmap: bandwidth
  amplification factor 7 to 28):
  <https://www.cisa.gov/news-events/alerts/2014/01/17/udp-based-amplification-attacks>
  and the alert text as archived: <https://seclists.org/cert/2017/236>
* CVE-2017-8779 (rpcbomb):
  <https://security-tracker.debian.org/tracker/CVE-2017-8779>

## License

MIT, as the rest of this repository. See `../LICENSE`.
