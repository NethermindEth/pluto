#!/usr/bin/env python3
"""Render results.json into a Markdown report; gate CI on baseline regressions.

Exit codes:
  0 - OK (SUBOPTIMAL flags alone never fail the run; they are the work queue)
  1 - harness error (bad inputs, incomparable baseline)
  2 - regression: a pair's ratio worsened more than --regression-threshold
      relative to the ratio recorded in --baseline
"""

import argparse
import json
import pathlib
import sys


def fmt_ns(ns, unit="ns"):
    if ns is None:
        return "-"
    if unit == "bytes":
        if ns < 1_048_576:
            return f"{ns / 1_024:.0f} KiB"
        return f"{ns / 1_048_576:.1f} MiB"
    if ns < 1_000:
        return f"{ns:.0f} ns"
    if ns < 1_000_000:
        return f"{ns / 1_000:.2f} µs"
    if ns < 1_000_000_000:
        return f"{ns / 1_000_000:.2f} ms"
    return f"{ns / 1_000_000_000:.2f} s"


def fmt_ratio(ratio):
    return f"{ratio:.2f}x" if ratio is not None else "-"


def load_baseline(path, meta):
    baseline = json.loads(pathlib.Path(path).read_text())
    base_meta = baseline.get("meta", {})
    for key in ("os", "arch"):
        if base_meta.get(key) != meta.get(key):
            print(
                f"render: baseline {key}={base_meta.get(key)} does not match "
                f"current {key}={meta.get(key)}; refusing to compare",
                file=sys.stderr,
            )
            sys.exit(1)

    return {r["id"]: r.get("ratio") for r in baseline.get("results", [])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results")
    parser.add_argument("--baseline", help="blessed results.json to gate against")
    parser.add_argument("--regression-threshold", type=float, default=1.10)
    parser.add_argument("-o", "--output", required=True)
    args = parser.parse_args()

    data = json.loads(pathlib.Path(args.results).read_text())
    meta = data["meta"]
    results = data["results"]

    baseline_ratios = load_baseline(args.baseline, meta) if args.baseline else {}

    lines = ["# Pluto vs Charon performance report", ""]
    lines.append(f"- date: {meta.get('date')}")
    lines.append(f"- host: {meta.get('host')} ({meta.get('os')}/{meta.get('arch')})")
    lines.append(f"- rustc: {meta.get('rustc')}")
    lines.append(f"- go: {meta.get('go')}")
    lines.append(f"- git: {meta.get('git_sha')}")
    lines.append("")

    suboptimal = [r for r in results if r["status"] == "SUBOPTIMAL"]
    if suboptimal:
        lines.append("## Work on these (Pluto slower than Charon)")
        lines.append("")
        lines.append("| pair | pluto | charon | ratio | workload |")
        lines.append("|---|---|---|---|---|")
        for r in sorted(suboptimal, key=lambda r: -(r["ratio"] or 0)):
            lines.append(
                f"| **{r['id']}** | {fmt_ns(r['pluto']['ns'])} "
                f"| {fmt_ns(r['charon']['ns'])} | **{fmt_ratio(r['ratio'])}** "
                f"| {r.get('workload') or ''} |"
            )
        lines.append("")
    else:
        lines.append("## No pairs flagged SUBOPTIMAL")
        lines.append("")

    regressions = []

    for tier in sorted({r["tier"] for r in results}):
        tier_results = [r for r in results if r["tier"] == tier]
        comparable = [r for r in tier_results if r["ratio"] is not None]
        single_sided = [r for r in tier_results if r["ratio"] is None]

        lines.append(f"## Tier {tier}")
        lines.append("")
        header = "| pair | pluto | charon | ratio | flag |"
        separator = "|---|---|---|---|---|"
        if baseline_ratios:
            header += " vs baseline |"
            separator += "---|"
        lines.append(header)
        lines.append(separator)

        for r in sorted(comparable, key=lambda r: -r["ratio"]):
            flag = r["status"] if r["status"] != "OK" else ""
            unit = r.get("unit", "ns")
            row = (
                f"| {r['id']} | {fmt_ns(r['pluto']['ns'], unit)} "
                f"| {fmt_ns(r['charon']['ns'], unit)} | {fmt_ratio(r['ratio'])} | {flag} |"
            )
            if baseline_ratios:
                base = baseline_ratios.get(r["id"])
                if base is not None and r["ratio"] is not None:
                    delta = r["ratio"] / base
                    row += f" {delta:+.1%} |".replace("%", "%")
                    row = row.replace("+-", "-")
                    if delta > args.regression_threshold:
                        regressions.append((r["id"], base, r["ratio"]))
                else:
                    row += " new |"
            lines.append(row)

        if single_sided:
            lines.append("")
            lines.append("Informational (single-sided):")
            lines.append("")
            for r in single_sided:
                side = r["pluto"] or r["charon"]
                lines.append(
                    f"- `{r['id']}` ({r['status']}): {fmt_ns(side['ns'], r.get('unit', 'ns'))}"
                )

        lines.append("")

    if regressions:
        lines.append("## Regressions vs baseline")
        lines.append("")
        for rid, base, current in regressions:
            lines.append(f"- `{rid}`: ratio {base:.2f}x -> {current:.2f}x")
        lines.append("")

    pathlib.Path(args.output).write_text("\n".join(lines))
    print(f"render: wrote {args.output}", file=sys.stderr)

    if regressions:
        print(f"render: {len(regressions)} regression(s) vs baseline", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
