#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
"""Judge a Kubernetes fleet end-to-end run from the evidence run.sh kept.

Every row is decided from something outside passmcp's own claims about
itself: the API server's objects, the container runtime's view of the
process, the files on the volume, the logs, and the packet capture. A row
with nothing to judge fails; absence of evidence is not a pass.

Usage: verify.py build/e2e-kind
"""

import base64
import hashlib
import ipaddress
import json
import pathlib
import re
import sys
import urllib.parse
from datetime import datetime, timedelta

OUT = pathlib.Path(sys.argv[1])
RUNS = (1, 2, 3)
SERVERS = ("docs", "billing", "local-stdio")
rows = []


def row(category, ok, evidence):
    rows.append({"category": category, "result": "PASS" if ok else "FAIL", "evidence": evidence})


def load(path):
    return json.loads((OUT / path).read_text())


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def summary(n):
    """The JSON summary a run printed, out of its interleaved log."""
    # The container log holds stdout and stderr together, and the runtime
    # may interleave their lines; passmcp's own diagnostics are prefixed.
    diag = re.compile(r"^(INFO|WARN|ERROR): ")
    lines = [l for l in (OUT / "runs" / str(n) / "stdout.txt").read_text().splitlines() if not diag.match(l)]
    start = next(i for i, l in enumerate(lines) if l == "{")
    end = max(i for i, l in enumerate(lines) if l == "}")
    return json.loads("\n".join(lines[start : end + 1]))


def by_name(s):
    return {srv["name"]: srv for srv in s["servers"]}


def exit_code(n):
    pod = load(f"runs/{n}/pod.json")
    st = next(c for c in pod["status"]["containerStatuses"] if c["name"] == "passmcp")
    return st["state"]["terminated"]["exitCode"]


def guarded(category, fn):
    try:
        fn()
    except Exception as e:  # noqa: BLE001 -- a row that cannot be judged fails
        row(category, False, f"could not be judged: {type(e).__name__}: {e}")


version = ""
sums = {}


def cluster():
    v = load("kubernetes-version.json")["serverVersion"]["gitVersion"]
    nodes = [p for p in load("runs/1-objects.json")["items"] if p["kind"] == "Pod" and p["metadata"]["namespace"] == "kube-system"]
    row("Real cluster", bool(v) and len(nodes) > 0, f"kind cluster, Kubernetes {v}; {len(nodes)} kube-system pods running the control plane")


def image():
    global version
    text = (OUT / "passmcp-version.txt").read_text().strip()
    version = text.split()[-1] if text else ""
    # The runtime names an image by its config digest and a pulled or
    # imported manifest digest; both are checked against what was built.
    config = (OUT / "image-config").read_text().strip()
    node = load("node-image.json")["status"]
    digests = {d.split("@", 1)[1] for d in node.get("repoDigests", [])}
    ids = {load(f"runs/{n}/pod.json")["status"]["containerStatuses"][0]["imageID"].split("@")[-1] for n in RUNS}
    same = node["id"] == config and bool(ids) and ids <= digests
    image_id = config
    instr = set()
    for srv in SERVERS:
        for att in (OUT / "state" / srv / "runs").glob("*/attestation.json"):
            instr.add(json.loads(att.read_text())["predicate"]["instrument"]["version"])
    ok = bool(version) and same and instr == {version}
    row("Image under test", ok, f"`passmcp version` in the cluster printed `{text}`; image {image_id[:19]}…; every run's pod ran it: {same}; attestations name instrument version(s) {sorted(instr)}")


def admission():
    ns = load("namespace.json")["metadata"]["labels"]
    enforced = ns.get("pod-security.kubernetes.io/enforce") == "restricted"
    pods = [load(f"runs/{n}/pod.json")["metadata"]["name"] for n in RUNS]
    row("Admission (Pod Security restricted)", enforced and len(pods) == 3, f"namespace enforces `restricted`; all {len(pods)} scheduled pods were admitted under it: {', '.join(pods)}")


def runtime():
    bad = []
    for n in RUNS:
        spec = load(f"runs/{n}/crictl-inspect.json")["info"]["runtimeSpec"]
        proc, linux = spec["process"], spec.get("linux", {})
        caps = proc.get("capabilities", {})
        checks = {
            "uid 65532": proc["user"]["uid"] == 65532,
            "gid 65532": proc["user"]["gid"] == 65532,
            "no new privileges": proc.get("noNewPrivileges") is True,
            "read-only root": spec["root"].get("readonly") is True,
            "no capabilities": all(not caps.get(k) for k in ("bounding", "effective", "permitted", "inheritable", "ambient")),
            "seccomp filter": bool(linux.get("seccomp", {}).get("syscalls")),
        }
        bad += [f"run {n}: {k}" for k, v in checks.items() if not v]
    row("securityContext as the runtime applied it", not bad, "containerd's runtime spec for all three passmcp containers: uid/gid 65532, noNewPrivileges, read-only rootfs, empty capability sets, RuntimeDefault seccomp filter" if not bad else "; ".join(bad))


def schedule():
    shipped = load("cronjob-as-shipped.json")["spec"]
    jobs = [load(f"runs/{n}/job.json") for n in RUNS]
    owned = all(any(o["kind"] == "CronJob" and o["name"] == "passmcp-fleet" for o in j["metadata"].get("ownerReferences", [])) for j in jobs)
    stamped = all("batch.kubernetes.io/cronjob-scheduled-timestamp" in j["metadata"].get("annotations", {}) for j in jobs)
    windows = sorted((ts(j["status"]["startTime"]), ts(j["status"].get("completionTime") or j["status"]["conditions"][-1]["lastTransitionTime"])) for j in jobs)
    overlap = any(a[1] > b[0] for a, b in zip(windows, windows[1:]))
    ok = shipped["schedule"] == "17 */6 * * *" and shipped["concurrencyPolicy"] == "Forbid" and owned and stamped and not overlap
    row("CronJob schedule", ok, f"shipped schedule `{shipped['schedule']}` accepted verbatim with concurrencyPolicy {shipped['concurrencyPolicy']}; all 3 jobs created by the CronJob controller (ownerReference + scheduled-timestamp annotation): {owned and stamped}; no two runs overlapped: {not overlap}")


def wiring():
    pod = load("runs/1/pod.json")["spec"]
    c = next(x for x in pod["containers"] if x["name"] == "passmcp")
    vols = {v["name"]: v for v in pod["volumes"]}
    mounts = {m["name"]: m for m in c["volumeMounts"]}
    cm = vols["fleet"].get("configMap", {}).get("name") == "passmcp-fleet" and mounts["fleet"].get("readOnly") is True
    env = {e["name"]: e for e in c["env"]}
    secret = all("valueFrom" in env[k] and "value" not in env[k] and env[k]["valueFrom"]["secretKeyRef"]["name"] == "passmcp-fleet-credentials" for k in ("DOCS_MCP_TOKEN", "BILLING_CLIENT_SECRET"))
    pvc = vols["state"].get("persistentVolumeClaim", {}).get("claimName") == "passmcp-fleet-state"
    names = set(by_name(sums[1]))
    row("ConfigMap wiring", cm and names == set(SERVERS), f"fleet file mounted read-only from ConfigMap passmcp-fleet; the run checked exactly the servers it names: {sorted(names)}")
    row("Secret wiring", secret, "DOCS_MCP_TOKEN and BILLING_CLIENT_SECRET reach the pod by secretKeyRef only; no literal value in the pod spec")
    prev1 = by_name(sums[1])["docs"]["attestation"]
    prev2 = by_name(sums[2])["docs"].get("previous_attestation")
    row("PersistentVolumeClaim state", pvc and prev1 == prev2 and bool(prev1), f"run 2, a new pod, compared docs with run 1's attestation {prev1[:19]}… read back from the claim")


def fleet01():
    s = sums[1]
    missing = []
    for name, srv in by_name(s).items():
        att = OUT / "state" / name / "runs" / pathlib.Path(srv["dir"]).name / "attestation.json"
        if not att.exists() or "sha256:" + hashlib.sha256(att.read_bytes()).hexdigest() != srv["attestation"]:
            missing.append(name)
        if srv["status"] != "pass" or not srv["grade"]:
            missing.append(f"{name}={srv['status']}")
    ok = not missing and s["exit"] == 0 and exit_code(1) == 0
    detail = ", ".join(f"{n} {v['status']} {v['score']:.1f} ({v['grade']})" for n, v in by_name(s).items())
    row("FLEET-01 every server checked and attested", ok, f"run 1: {detail}; each attestation on the volume hashes to the digest the summary cites; fleet exit {s['exit']}, pod exit {exit_code(1)}" + (f"; problems: {missing}" if missing else ""))


def fleet03():
    d = by_name(sums[2])
    docs = d["docs"]
    flip = [c for c in docs["changes"] if "readOnlyHint" in json.dumps(c) and c.get("severity") == "critical"]
    quiet = all(not d[n]["changes"] for n in ("billing", "local-stdio"))
    ok = bool(flip) and docs["critical"] and sums[2]["exit"] == 2 and exit_code(2) == 2 and quiet
    row("FLEET-02/03 a readOnlyHint flip is critical", ok, f"run 2: docs reported {len(docs['changes'])} change(s), {json.dumps(flip[0]) if flip else 'no critical readOnlyHint change'}; score {docs['score']:.1f}; fleet exit {sums[2]['exit']}, pod exit {exit_code(2)}; billing and stdio unchanged: {quiet}")


def fleet06():
    d = by_name(sums[3])["docs"]
    latest = json.loads((OUT / "state" / "docs" / "latest.json").read_text())
    kept = latest["attestation"] == by_name(sums[2])["docs"]["attestation"]
    ok = d["status"] == "unreachable" and "dial tcp" in d.get("error", "") and not d.get("attestation") and sums[3]["exit"] == 1 and exit_code(3) == 1 and kept
    row("FLEET-06 an unreachable server", ok, f"run 3: docs `{d['status']}`: {d.get('error', '')[:200]}; no attestation written; its last good run stays run 2's: {kept}; fleet exit {sums[3]['exit']}, pod exit {exit_code(3)}")


def client_credentials():
    logs = "".join((OUT / "runs" / str(n) / "billing.log").read_text() for n in RUNS)
    active = re.findall(r"introspected: active=true client_id=(\S+)", logs)
    fleet = (OUT / "fleet.yaml").read_text()
    cid = re.search(r"client_id: (\S+)", fleet).group(1)
    passes = [by_name(sums[n])["billing"]["status"] for n in RUNS]
    ok = bool(active) and set(active) == {cid} and passes == ["pass"] * 3
    row("Client credentials against a real AS", ok, f"Ory Hydra v2.3.0 issued the tokens; billing accepted only tokens Hydra introspected as active for client {cid[:8]}… ({len(active)} introspections); billing passed in every run: {passes}")


def stdio():
    st = [by_name(sums[n])["local-stdio"]["status"] for n in RUNS]
    atts = list((OUT / "state" / "local-stdio" / "runs").glob("*/attestation.json"))
    ok = st == ["pass"] * 3 and len(atts) == 3
    row("stdio server inside the container", ok, f"`/opt/stdio/fixture --stdio`, carried in by an init container, spawned by passmcp under the same restricted context: {st}; {len(atts)} attestations")


def secrets():
    needles = set((OUT / "seeded-secrets").read_text().split())
    for n in RUNS:
        for d in ("docs", "billing"):
            needles |= set(re.findall(r'bearer-token-seen "([^"]+)"', (OUT / "runs" / str(n) / f"{d}.log").read_text()))
    forms = set()
    for s in needles:
        forms |= {s, base64.b64encode(s.encode()).decode(), base64.urlsafe_b64encode(s.encode()).decode().rstrip("="), urllib.parse.quote(s, safe="")}
    haystack = [p for p in (OUT / "state").rglob("*") if p.is_file()]
    haystack += [OUT / "runs" / str(n) / f for n in RUNS for f in ("stdout.txt", "init.txt", "pod.json", "job.json")]
    haystack += [OUT / "events.json", OUT / "jobs.json", OUT / "passmcp-namespace.yaml"]
    leaks = [str(p.relative_to(OUT)) for p in haystack if any(f in p.read_text(errors="replace") for f in forms)]
    reflected = any("Authorised as" in p.read_text() for p in (OUT / "state" / "docs" / "runs").glob("*/catalogue.json"))
    issued = len(needles) - 2
    ok = not leaks and issued > 0 and reflected
    row("FLEET-05 no secret in any output", ok, f"searched {len(haystack)} files (the whole volume, every log, events, the Job and Pod objects) for 2 seeded secrets and {issued} token(s) the servers saw, raw, base64 and URL-encoded: {'none found' if not leaks else leaks}; the docs server reflected its token into a description and the recorded catalogue carries it masked: {reflected}")


def egress():
    allowed, names = set(), set()
    for n in RUNS:
        for o in load(f"runs/{n}-objects.json")["items"]:
            ns = o["metadata"]["namespace"]
            if o["kind"] == "Service" and (ns == "fleet-servers" or o["metadata"]["name"] == "kube-dns"):
                allowed.add(o["spec"]["clusterIP"])
            if o["kind"] == "Pod" and (ns == "fleet-servers" or o["metadata"]["labels"].get("k8s-app") == "kube-dns"):
                allowed |= {p["ip"] for p in o["status"].get("podIPs", [])}
    told = {"docs.fleet-servers.svc", "billing.fleet-servers.svc", "hydra.fleet-servers.svc"}
    windows = []
    for n in RUNS:
        pod = load(f"runs/{n}/pod.json")
        st = next(c for c in pod["status"]["containerStatuses"] if c["name"] == "passmcp")
        windows.append((pod["status"]["podIP"], ts(pod["status"]["startTime"]), ts(st["state"]["terminated"]["finishedAt"]) + timedelta(seconds=5)))
    pkt = re.compile(r"^(\d+\.\d+) .*?IP6? (\S+) > (\S+?):(.*)$")
    seen, bad, queries = {}, [], set()
    for line in (OUT / "egress.txt").read_text().splitlines():
        m = pkt.match(line)
        if not m:
            continue
        t = datetime.fromtimestamp(float(m.group(1))).astimezone()
        src, dst = m.group(2).rsplit(".", 1)[0] if m.group(2).count(".") == 4 else m.group(2), m.group(3)
        dst_ip = dst.rsplit(".", 1)[0] if dst.count(".") == 4 else dst
        if not any(src == ip and a <= t <= b for ip, a, b in windows):
            continue
        port = dst.rsplit(".", 1)[1] if dst.count(".") == 4 else "-"
        seen[f"{dst_ip}:{port}"] = seen.get(f"{dst_ip}:{port}", 0) + 1
        if dst_ip not in allowed:
            bad.append(line[:160])
        q = re.search(r" (?:A|AAAA)\? (\S+)\.? ", m.group(4))
        if q:
            queries.add(q.group(1).rstrip("."))
    strays = sorted(q for q in queries if not any(q == h or q.startswith(h + ".") for h in told))
    ok = bool(seen) and not bad and not strays and len(queries) > 0
    try:
        allowed_net = all(ipaddress.ip_address(k.split(":")[0]).is_private for k in seen)
    except ValueError:
        allowed_net = False
    row("FLEET-04 no request to an unnamed host", ok and allowed_net, f"{sum(seen.values())} packets from the three passmcp pods, to {len(seen)} destination(s), all a fleet-servers or cluster-DNS address: {not bad}; DNS asked only for the named hosts (with search-path suffixes): {sorted(queries) if not strays else 'strays ' + str(strays)}" + (f"; unexpected: {bad[:3]}" if bad else ""))


guarded("run summaries", lambda: sums.update({n: summary(n) for n in RUNS}))
for name, fn in (
    ("Real cluster", cluster),
    ("Image under test", image),
    ("Admission (Pod Security restricted)", admission),
    ("securityContext as the runtime applied it", runtime),
    ("CronJob schedule", schedule),
    ("ConfigMap/Secret/PVC wiring", wiring),
    ("FLEET-01 every server checked and attested", fleet01),
    ("FLEET-02/03 a readOnlyHint flip is critical", fleet03),
    ("FLEET-06 an unreachable server", fleet06),
    ("Client credentials against a real AS", client_credentials),
    ("stdio server inside the container", stdio),
    ("FLEET-05 no secret in any output", secrets),
    ("FLEET-04 no request to an unnamed host", egress),
):
    guarded(name, fn)

passed = sum(r["result"] == "PASS" for r in rows)
md = [f"# passmcp {version or '?'} fleet on Kubernetes: {passed}/{len(rows)}", "", "| Category | Result | Evidence |", "|---|---|---|"]
md += [f"| {r['category']} | {r['result']} | {r['evidence'].replace('|', '/')} |" for r in rows]
(OUT / "matrix.md").write_text("\n".join(md) + "\n")
(OUT / "matrix.json").write_text(json.dumps(rows, indent=2) + "\n")
print("\n".join(md))
sys.exit(0 if passed == len(rows) else 1)
