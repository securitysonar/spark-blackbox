#!/usr/bin/env python3
"""Link tool calls in the FGAT journal to host process executions (auditd).

Step-0 decision (b): rig stays unmodified, so the journal has no process IDs.
The link is by time and parentage: auditd records every execve by the tool
container's UID (rule key bbx-tools), and each execve whose timestamp falls
between a tool call's intent and result records is attributed to that call.
Executions that fall outside every window are listed separately; so are tool
calls with no execution (expected for tools that don't start a process, such
as read_file in toolhost).

Limits: attribution is by time, so it assumes tool calls don't overlap (rig
runs them one at a time); the PID chain is reported, not used to decide.

Usage:
  python3 pid_link.py --journal campaign/evidence/audit_journal.jsonl \
      --session bbx-V0A-xxxxxx [--audit-log /var/log/audit/audit.log]
"""
import argparse
import json
import re
from collections import defaultdict

MSG = re.compile(r"msg=audit\((\d+\.\d+):(\d+)\)")
FIELD = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')


def parse_audit(path, key):
    events = defaultdict(dict)
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = MSG.search(line)
            if not m:
                continue
            ts, serial = float(m.group(1)), m.group(2)
            typ = line.split(" ", 1)[0].removeprefix("type=")
            fields = {k: v.strip('"') for k, v in FIELD.findall(line)}
            ev = events[serial]
            ev["ts"] = ts
            if typ == "SYSCALL":
                ev.update(pid=fields.get("pid"), ppid=fields.get("ppid"), uid=fields.get("uid"),
                          exe=fields.get("exe"), comm=fields.get("comm"), key=fields.get("key"),
                          success=fields.get("success"))
            elif typ == "EXECVE":
                argc = int(fields.get("argc", "0"))
                args = []
                for i in range(argc):
                    v = fields.get(f"a{i}", "")
                    if re.fullmatch(r"[0-9A-F]+", v) and len(v) % 2 == 0 and not v.isdigit():
                        try:
                            v = bytes.fromhex(v).decode("utf-8", "replace")
                        except ValueError:
                            pass
                    args.append(v)
                ev["argv"] = args
    return sorted((e for e in events.values() if e.get("key") == key), key=lambda e: e["ts"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--journal", required=True)
    ap.add_argument("--session", required=True)
    ap.add_argument("--audit-log", default="/var/log/audit/audit.log")
    ap.add_argument("--key", default="bbx-tools")
    ap.add_argument("--json", help="write the linkage here as JSON")
    a = ap.parse_args()

    with open(a.journal, encoding="utf-8") as f:
        recs = [r for r in (json.loads(l) for l in f if l.strip()) if r.get("session_id") == a.session]
    intents = {}
    calls = []
    for r in recs:
        if r["kind"] == "intent":
            intents.setdefault((r["turn"], r["tool"]), []).append(r)
        elif r["kind"] == "result":
            i = intents.get((r["turn"], r["tool"]), [])
            start = i.pop(0)["ts"] if i else r["ts"]
            calls.append({"turn": r["turn"], "seq": r["seq"], "tool": r["tool"], "args": r.get("args"),
                          "start": start, "end": r["ts"], "execs": []})
    if not calls:
        raise SystemExit(f"no tool calls for session {a.session}")
    t_min, t_max = calls[0]["start"] - 5, calls[-1]["end"] + 5
    execs = [e for e in parse_audit(a.audit_log, a.key) if t_min <= e["ts"] <= t_max]

    unlinked = []
    for e in execs:
        for c in calls:
            if c["start"] <= e["ts"] <= c["end"]:
                c["execs"].append(e)
                break
        else:
            unlinked.append(e)

    linked = sum(len(c["execs"]) for c in calls)
    print(f"session {a.session}: {len(calls)} tool calls, {len(execs)} execve events (uid "
          f"{sorted({e.get('uid') for e in execs})}), {linked} linked, {len(unlinked)} unlinked")
    by_tool = defaultdict(lambda: [0, 0])
    for c in calls:
        by_tool[c["tool"]][0] += 1
        by_tool[c["tool"]][1] += bool(c["execs"])
    for t, (n, with_exec) in sorted(by_tool.items()):
        print(f"  {t}: {n} calls, {with_exec} with at least one execve")
    for c in calls:
        if c["tool"] == "run":
            print(f"\nturn {c['turn']} seq {c['seq']} run: {c['args'].get('command') if c['args'] else ''}")
            for e in c["execs"]:
                print(f"    {e['ts']:.3f} pid {e.get('pid')} ppid {e.get('ppid')} {e.get('exe')} "
                      f"{' '.join(e.get('argv', []))[:160]}")
    if unlinked:
        print("\nunlinked execve events:")
        for e in unlinked:
            print(f"    {e['ts']:.3f} pid {e.get('pid')} ppid {e.get('ppid')} {e.get('exe')} "
                  f"{' '.join(e.get('argv', []))[:160]}")
    if a.json:
        with open(a.json, "w") as f:
            json.dump({"session": a.session, "calls": calls, "unlinked": unlinked}, f, indent=1)


if __name__ == "__main__":
    main()
