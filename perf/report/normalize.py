#!/usr/bin/env python3
"""Normalize heterogeneous benchmark outputs into a single results.json.

Inputs:
  - criterion:  target/criterion/**/new/{benchmark.json,estimates.json}
  - go:         `go test -bench` text output (ns/op, B/op, allocs/op)
  - hyperfine:  perf/out/hyperfine/*.json (tier 3 CLI pairs, optional)
  - dkg:        perf/out/dkg-times.json (tier 3 ceremony timings, optional)

Only pairs listed in perf/pairs.json are emitted (plus tier-3 inputs, which
carry their own ids). Uses Python stdlib only.
"""

import argparse
import datetime
import json
import pathlib
import platform
import re
import statistics
import subprocess
import sys

GO_BENCH_RE = re.compile(
    r"^Benchmark(\S+?)(?:-\d+)?\s+\d+\s+([\d.]+)\s+ns/op"
    r"(?:\s+([\d.]+)\s+B/op\s+([\d.]+)\s+allocs/op)?"
)


def run_cmd(args):
    try:
        return subprocess.run(
            args, capture_output=True, text=True, check=True, timeout=30
        ).stdout.strip()
    except Exception:  # noqa: BLE001 - meta fields are best-effort
        return None


def collect_meta(repo_root):
    return {
        "date": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "host": platform.node(),
        "os": platform.system().lower(),
        "arch": platform.machine(),
        "rustc": run_cmd(["rustc", "--version"]),
        "go": run_cmd(["go", "version"]),
        "git_sha": run_cmd(["git", "-C", str(repo_root), "rev-parse", "--short", "HEAD"]),
    }


def parse_criterion(criterion_dir):
    """Return {full_id: mean_ns} from criterion's on-disk estimates."""
    results = {}
    root = pathlib.Path(criterion_dir)
    if not root.is_dir():
        return results

    for bench_json in root.rglob("new/benchmark.json"):
        estimates = bench_json.parent / "estimates.json"
        if not estimates.is_file():
            continue

        try:
            full_id = json.loads(bench_json.read_text())["full_id"]
            mean_ns = json.loads(estimates.read_text())["mean"]["point_estimate"]
        except (json.JSONDecodeError, KeyError):
            continue

        results[full_id] = float(mean_ns)

    return results


def parse_go_bench(go_file):
    """Return {name: {ns, bytes_alloc, allocs}} with medians across -count runs."""
    samples = {}
    path = pathlib.Path(go_file)
    if not path.is_file():
        return {}

    for line in path.read_text().splitlines():
        m = GO_BENCH_RE.match(line.strip())
        if not m:
            continue

        name, ns, bytes_alloc, allocs = m.groups()
        entry = samples.setdefault(name, {"ns": [], "bytes": [], "allocs": []})
        entry["ns"].append(float(ns))
        if bytes_alloc is not None:
            entry["bytes"].append(float(bytes_alloc))
            entry["allocs"].append(float(allocs))

    results = {}
    for name, entry in samples.items():
        results[name] = {
            "ns": statistics.median(entry["ns"]),
            "bytes_alloc": statistics.median(entry["bytes"]) if entry["bytes"] else None,
            "allocs": statistics.median(entry["allocs"]) if entry["allocs"] else None,
        }

    return results


def parse_hyperfine(hyperfine_dir):
    """Return [{id, pluto_ns, charon_ns}] from hyperfine export JSONs.

    Convention: one JSON per pair, filename `tier3__cli__create_enr.json` maps
    to id `tier3/cli/create_enr`; commands are named `pluto` and `charon` via
    hyperfine's --command-name.
    """
    out = []
    root = pathlib.Path(hyperfine_dir) if hyperfine_dir else None
    if not root or not root.is_dir():
        return out

    for f in sorted(root.glob("*.json")):
        try:
            data = json.loads(f.read_text())
        except json.JSONDecodeError:
            continue

        times = {}
        for res in data.get("results", []):
            name = res.get("command", "")
            if name in ("pluto", "charon"):
                times[name] = float(res["median"]) * 1e9

        if "pluto" in times and "charon" in times:
            out.append(
                {
                    "id": f.stem.replace("__", "/"),
                    "pluto_ns": times["pluto"],
                    "charon_ns": times["charon"],
                }
            )

    return out


def parse_extra(files):
    """Return [{id, unit, pluto_ns, charon_ns}] from extra-timings JSONs.

    Each file holds a list of entries: {id, unit ("s"|"ns"|"bytes"),
    pluto_value, charon_value}. Values in seconds are converted to ns; other
    units pass through with `unit` preserved.
    """
    out = []
    for f in files or []:
        path = pathlib.Path(f)
        if not path.is_file():
            continue

        for entry in json.loads(path.read_text()):
            unit = entry.get("unit", "ns")
            scale = 1e9 if unit == "s" else 1.0
            item = {"id": entry["id"], "unit": "ns" if unit == "s" else unit}
            if entry.get("pluto_value") is not None:
                item["pluto_ns"] = float(entry["pluto_value"]) * scale
            if entry.get("charon_value") is not None:
                item["charon_ns"] = float(entry["charon_value"]) * scale
            out.append(item)

    return out


def status_for(pluto_ns, charon_ns, threshold):
    if pluto_ns is None and charon_ns is None:
        return "MISSING"
    if charon_ns is None:
        return "PLUTO_ONLY"
    if pluto_ns is None:
        return "CHARON_ONLY"
    return "SUBOPTIMAL" if pluto_ns / charon_ns > threshold else "OK"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pairs", required=True)
    parser.add_argument("--criterion", help="criterion output dir (target/criterion)")
    parser.add_argument("--go", help="go test -bench output file")
    parser.add_argument("--hyperfine", help="dir with hyperfine export JSONs")
    parser.add_argument(
        "--extra",
        nargs="*",
        help="extra-timings JSONs (dkg-times.json, cli-extra.json)",
    )
    parser.add_argument("--suboptimal-threshold", type=float, default=1.15)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("-o", "--output", required=True)
    args = parser.parse_args()

    pairs = json.loads(pathlib.Path(args.pairs).read_text())["pairs"]
    criterion = parse_criterion(args.criterion) if args.criterion else {}
    go_bench = parse_go_bench(args.go) if args.go else {}

    results = []
    for pair in pairs:
        rust_id = pair.get("rust", pair["id"])
        pluto_ns = criterion.get(rust_id)
        go_entry = go_bench.get(pair["go"]) if pair.get("go") else None

        pluto = {"ns": pluto_ns} if pluto_ns is not None else None
        charon = (
            {
                "ns": go_entry["ns"],
                "bytes_alloc": go_entry["bytes_alloc"],
                "allocs": go_entry["allocs"],
            }
            if go_entry
            else None
        )

        charon_ns = go_entry["ns"] if go_entry else None
        status = status_for(pluto_ns, charon_ns, args.suboptimal_threshold)
        if status == "MISSING":
            continue

        results.append(
            {
                "id": pair["id"],
                "tier": pair["tier"],
                "workload": pair.get("workload"),
                "pluto": pluto,
                "charon": charon,
                "ratio": (
                    round(pluto_ns / charon_ns, 3)
                    if pluto_ns is not None and charon_ns is not None
                    else None
                ),
                "status": status,
            }
        )

    for item in parse_hyperfine(args.hyperfine) + parse_extra(args.extra):
        pluto_ns = item.get("pluto_ns")
        charon_ns = item.get("charon_ns")
        results.append(
            {
                "id": item["id"],
                "tier": 3,
                "workload": None,
                "unit": item.get("unit", "ns"),
                "pluto": {"ns": pluto_ns} if pluto_ns is not None else None,
                "charon": {"ns": charon_ns} if charon_ns is not None else None,
                "ratio": (
                    round(pluto_ns / charon_ns, 3)
                    if pluto_ns is not None and charon_ns is not None
                    else None
                ),
                "status": status_for(pluto_ns, charon_ns, args.suboptimal_threshold),
            }
        )

    output = {"meta": collect_meta(args.repo_root), "results": results}
    pathlib.Path(args.output).write_text(json.dumps(output, indent=2) + "\n")

    print(f"normalize: wrote {len(results)} results to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
