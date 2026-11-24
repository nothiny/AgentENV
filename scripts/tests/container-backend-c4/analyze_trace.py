"""Summarize a profile.sh strace: external programs by phase and syscall counts."""
import collections, re, sys
out = sys.argv[1] if len(sys.argv) > 1 else "/state/profile/default"
marks = [l.split() for l in open(f"{out}/marks")]
marks = [(float(t), name) for t, name in marks]
start = marks[0][0]
phases = [("create", marks[0][0], marks[1][0]), ("exec", marks[1][0], marks[2][0]),
          ("delete", marks[2][0], marks[3][0])]
line_re = re.compile(r"^(\d+)\s+(\d+\.\d+)\s+(\w+)\((.*?)\)\s+=\s+(-?\w+).*?(?:<(\d+\.\d+)>)?$")
execs, calls = [], collections.Counter()
for line in open(f"{out}/trace"):
    m = line_re.match(line.strip())
    if not m:
        continue
    pid, ts, name, args, ret, dur = m.groups()
    ts = float(ts)
    phase = next((p for p, a, b in phases if a <= ts <= b), None)
    if phase is None:
        continue
    calls[(phase, name)] += 1
    if name == "execve" and ret == "0":
        argv = re.findall(r'"((?:[^"\\]|\\.)*)"', args)
        prog = argv[0].rsplit("/", 1)[-1] if argv else "?"
        execs.append((ts - start, phase, prog, " ".join(argv[1:6])[:90]))
print("phase durations (ms):", {p: round((b - a) * 1000) for p, a, b in phases})
for phase in ("create", "exec", "delete"):
    items = [e for e in execs if e[1] == phase]
    progs = collections.Counter(e[2] for e in items)
    print(f"\n== {phase}: {len(items)} execve; by program: {dict(progs)}")
    for t, _, prog, args in items:
        print(f"  +{t*1000:8.1f} ms  {prog:<14} {args}")
print("\nsyscalls by phase:")
for (phase, name), n in sorted(calls.items()):
    print(f"  {phase:<7} {name:<10} {n}")
