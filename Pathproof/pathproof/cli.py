import argparse
import json
from pathlib import Path
import sys
from tempfile import mkdtemp
from collections import Counter

from .activity import change, demo, read_lab, repair
from .conformance import compare, online
from .fixtures import baseline, snapshot
from .io import read_snapshot, state_lock, write_json
from .passive import live
from .providers.aws import AWS
from .replay import measure, offline, plan
from .restore import lab_state
from .reports import LEVELS, exports, scan
from .selftest import selftest

KEYS = ("T1", "T2", "T3", "T4", "T5")


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(prog="pathproof")
    subs = cli.add_subparsers(dest="cmd", required=True)
    collect = subs.add_parser("collect")
    collect.add_argument("--regions", nargs="+", required=True)
    collect.add_argument("--out", type=Path, required=True)
    scan_cmd = subs.add_parser("scan")
    group = scan_cmd.add_mutually_exclusive_group()
    group.add_argument("--snapshot", type=Path)
    group.add_argument("--aws", action="store_true")
    scan_cmd.add_argument("--regions", nargs="+", default=["us-east-1"])
    scan_cmd.add_argument("--severity", choices=LEVELS, default="LOW")
    scan_cmd.add_argument("--mutelist", type=Path)
    replay = subs.add_parser("replay")
    replay.add_argument("scenario", choices=KEYS, nargs="?", default="T1")
    sources = replay.add_mutually_exclusive_group()
    sources.add_argument("--snapshot", type=Path)
    sources.add_argument("--aws-principal")
    replay.add_argument("--object-arn")
    replay.add_argument("--rehydrate", action="store_true")
    fix = subs.add_parser("fix")
    fix.add_argument("scenario", choices=KEYS)
    fix.add_argument("--preview", action="store_true")
    lab = subs.add_parser("lab")
    labs = lab.add_subparsers(dest="op", required=True)
    labs.add_parser("seed")
    for op in ("break", "fix"):
        labs.add_parser(op).add_argument("scenario", choices=KEYS)
    check = subs.add_parser("selftest")
    check.add_argument("--json", action="store_true")
    cf = subs.add_parser("conformance")
    cf.add_argument("--aws-principal")
    show = subs.add_parser("demo")
    show.add_argument("--narrate", action="store_true")
    for sub in (show, fix, replay):
        sub.add_argument("--backend", choices=("memory", "moto"), default="memory")
    for sub in (scan_cmd, show, fix):
        sub.add_argument("--risk", type=Path)
        sub.add_argument("--out", type=Path)
    for sub in (scan_cmd, replay, fix):
        sub.add_argument("--lab", type=Path, default=Path("lab.json"))
    for sub in labs.choices.values():
        sub.add_argument("--lab", type=Path, default=Path("lab.json"))
    return cli


def output(path: Path | None) -> Path:
    if path:
        return path
    root = Path("runs")
    root.mkdir(exist_ok=True)
    return Path(mkdtemp(dir=root, prefix="pathproof-")) / "evidence"


def display(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def run(args) -> int:
    if args.cmd == "collect":
        write_json(args.out, AWS().collect(list(dict.fromkeys(args.regions))))
        print(args.out)
    elif args.cmd == "lab":
        if args.op == "seed":
            with state_lock(args.lab):
                if args.lab.exists():
                    raise ValueError("Lab already exists. Select a new path to seed another lab.")
                write_json(args.lab, baseline())
            print("Seeded " + str(args.lab))
        else:
            display(change(args.lab, args.scenario, args.op == "break"))
    elif args.cmd == "scan":
        if args.snapshot:
            snap = read_snapshot(args.snapshot)
        elif args.aws:
            snap = AWS().collect(list(dict.fromkeys(args.regions)))
        else:
            snap = snapshot(read_lab(args.lab))
        out = output(args.out)
        out.mkdir(parents=True, exist_ok=False)
        write_json(out / "snapshot.json", snap)
        report = scan(snap, args.severity, args.mutelist, args.risk)
        exports(out, report)
        display(Counter(r["status"] for r in report["findings"] if r["visible"]))
        print(out / "report.html")
    elif args.cmd == "replay":
        if args.rehydrate and not args.snapshot:
            raise ValueError("--rehydrate requires a classroom snapshot.")
        if args.aws_principal:
            if args.scenario != "T1" or not args.object_arn:
                raise ValueError("AWS simulation requires T1 and an exact --object-arn.")
            display(live(args.aws_principal, args.object_arn))
        elif args.object_arn:
            raise ValueError("--object-arn requires --aws-principal.")
        elif args.snapshot:
            snap = read_snapshot(args.snapshot)
            result = (measure(lab_state(snap), plan(args.scenario), args.backend) if args.rehydrate
                      else offline(snap, args.scenario))
            display(result)
            if args.rehydrate and (not all(result["must_still_work"].values()) or
                                   args.scenario == "T1" and not result["verdict"]):
                return 1
        else:
            result = measure(read_lab(args.lab), plan(args.scenario), args.backend)
            display(result)
            if not all(result["must_still_work"].values()) or (args.scenario == "T1" and not result["verdict"]):
                return 1
    elif args.cmd == "fix":
        if args.preview:
            from .fixtures import toggle
            display(toggle(read_lab(args.lab), args.scenario, False)[1])
        else:
            out = output(args.out)
            result = repair(args.lab, args.scenario, args.backend, out, args.risk)
            print(result["outcome"], out / "report.html")
            return int(result["outcome"] == "unresolved")
    elif args.cmd == "demo":
        out = output(args.out)
        results = demo(out, args.backend, args.narrate, args.risk)
        print(out / "report.html")
        return int(any(r["outcome"] != "verified" for r in results))
    elif args.cmd == "selftest":
        rows = selftest()
        if args.json:
            display(rows)
        else:
            for key, row in rows.items():
                print(key, "precision", row["precision"], "recall", row["recall"], "coverage", row["coverage"])
        return int(any(r["precision"] != 1 or r["recall"] != 1 or not r["unknown_is_manual"] for r in rows.values()))
    else:
        result = online(args.aws_principal) if args.aws_principal else compare()
        display(result)
        expected = sum(r["local"] != "UNKNOWN" for r in result["cases"])
        return int(result["local_matches"] != len(result["cases"]) or bool(args.aws_principal)
                   and result["aws_agreed"] != expected)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return run(args)
    except (ValueError, OSError, KeyError, RuntimeError, ImportError) as exc:
        print(f"PathProof: {exc}", file=sys.stderr)
    except Exception as exc:
        if type(exc).__module__.startswith(("botocore", "boto3")):
            print("AWS operation failed: " + type(exc).__name__, file=sys.stderr)
        else:
            raise
    return 2


def entry() -> None:
    raise SystemExit(main())
