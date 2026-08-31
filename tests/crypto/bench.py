#!/usr/bin/env python3
"""Run one crypto benchmark case and keep the evidence.

    bench.py --case crypto-chacha-poly-s2 -b 16
    bench.py --case crypto-chacha-poly-s2 -b 32
    bench.py --list

The `--case` name comes from ci/testcases/crypto.yaml, which is the only place
that records which extension macros each implementation needs. Getting that set
wrong is silent -- the kernel runs, it just runs a different one -- so it is
read from the catalog rather than retyped.

What the catalog cannot supply is the measurement itself. Its cases are sized
for CI: one point, at the default shape. A per-block figure is a two-point
marginal fit at the recorded shape, so `--shape` defaults to the recorded
c2w4t16 rather than the catalog's, and block counts are overridden per run:

    for b in 16 32; do bench.py --case crypto-chacha-poly-s2 -b $b; done

A catalog case is also not always the configuration a recorded row was measured
in, and the difference is not small. `crypto-chacha-poly-s2` enables only the S2
engine, to isolate it; the measured S2 row was taken with `SYM_CHACHA` on as
well, and runs `-t37 -a20` shorter. Fitted side by side those give 1.08 c/B and
1.90 c/B -- a 43% spread from configuration alone, against a 4% noise floor. So
reproduce a recorded row from its own `extensions` and `opts` columns:

    bench.py --app chacha_poly -n 64 -b 16 -i 10 \
--configs "-DVX_CFG_EXT_SYM_ENABLE 
-DVX_CFG_EXT_AUTH_ENABLE \
-DVX_CFG_EXT_AUTH_POLY_ENABLE \
-DVX_CFG_EXT_SYM_CHACHA_ENABLE \
    
-DVX_CFG_EXT_SYM_CHACHA_S2_ENABLE"

and use `--case` for a quick, named, repeatable run of a case as CI defines it.

The full stdout goes to RUNS/logs/ under a timestamped name, and the
application's own <APP>_PERF: line is appended to RUNS/records.csv in the
columns of docs/proposals/data/crypto_measurements.csv plus provenance
(core_instrs, git, configs). RUNS defaults to build32/crypto_runs.

A row is recorded only for a run that exited 0, printed PASSED!, and produced
exactly one PERF line. The applications print PERF before they verify, so an
ungated PERF line can belong to a wrong answer. --expect-fail flips the check
for the one diagnostic that measures a deliberately wrong answer
(chacha_poly -i11).
"""

import argparse
import csv
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "ci"))
import testcase as tc  # noqa: E402  (needs ROOT/ci on the path first)

COLUMNS = ["app", "impl", "driver", "cores", "warps", "threads", "msgs",
           "blocks_per_msg", "blocks", "bytes", "cycles", "instrs",
           "core_instrs", "opts", "extensions", "git", "configs", "log"]

PERF_RE = re.compile(r"^[A-Z_]+_PERF: (.*)$", re.M)
SHAPE_RE = re.compile(r"^c(\d+)w(\d+)t(\d+)$")


# --- the catalog ------------------------------------------------------------

def catalog_cases(yaml_path=None):
    """Cases keyed by short name. A yaml lists each entry once per driver, but
    the two variants differ only in driver -- app, options and configs are
    shared -- so one entry per name is enough; the driver comes from --driver.
    """
    cases = tc.load_category(yaml_path) if yaml_path else [
        c for c in tc.load_all() if c.category == "crypto"]
    out = {}
    for case in cases:
        out.setdefault(case.id.split(":")[1], case)
    return out


def case_options(case):
    """The app options a case runs with: blackbox puts them in `args`,
    make-run in `vars: OPTS`."""
    return case.args or (case.vars or {}).get("OPTS", "")


def case_app(case):
    """The app directory name. blackbox spells it `crypto/aes_gcm`;
    make-run spells it `tests/crypto/aes_gcm`."""
    return os.path.basename(case.app or case.dir)


# --- option merging ---------------------------------------------------------

def split_options(text):
    """`-n64 -b4 -i10` -> {'n': '64', 'b': '4', 'i': '10'}, tolerating the
    detached `-b 4` spelling as well."""
    opts, pending = {}, None
    for token in text.split():
        if pending:
            opts[pending], pending = token, None
        elif token.startswith("-") and len(token) > 2:
            opts[token[1]] = token[2:]
        elif token.startswith("-"):
            pending = token[1]
    return opts


def join_options(opts):
    return " ".join("-{}{}".format(k, v) for k, v in sorted(opts.items()))


# --- running ----------------------------------------------------------------

def shape_configs(shape):
    m = SHAPE_RE.match(shape)
    if not m:
        sys.exit("--shape must look like c2w4t16, got {!r}".format(shape))
    cores, warps, threads = m.groups()
    return ["-DVX_CFG_NUM_CORES=" + cores,
            "-DVX_CFG_NUM_WARPS=" + warps,
            "-DVX_CFG_NUM_THREADS=" + threads]


class Unrunnable(Exception):
    """This case cannot be run here, and why. Fatal on its own, skipped in a
    batch -- one unbuildable case should not end a sweep."""


def build_dir(build, app):
    """The app's directory inside the build tree, which must already be
    configured -- this script builds apps, not the tree."""
    if app == "crypto":
        raise Unrunnable("runs the whole tests/crypto family, not one app")
    if not os.path.exists(os.path.join(build, "config.mk")):
        sys.exit("{0} is not a configured build tree (no config.mk).\n"
                 "  mkdir -p {0} && cd {0} && ../configure --xlen=32"
                 .format(build))
    path = os.path.join(build, "tests", "crypto", app)
    if not os.path.isdir(path):
        # Only the directory is needed; this script builds the app inside it.
        # configure re-copies the test tree and is idempotent, so it is the fix
        # for a missing one. Not `make -C <build>` -- that is a whole-tree build
        # and stops in third_party on dependencies (cocogfx wants libpng) that
        # no crypto test touches.
        sys.exit("no {0} directory at {1}\n"
                 "  cd {2} && ../configure --xlen=32"
                 .format(app, path, build))
    return path


def execute_run(directory, driver, opts, configs, log_path, echo=True):
    """Run the case, writing to the log, and return the captured output.
    `echo` also mirrors it to stdout -- wanted for a single run, not for a
    batch, where the build output would bury the one line per case."""
    header = [
        "### bench.py {} {}".format(driver, opts or "(makefile default)"),
        "### cfg  {}".format(configs),
        "### date {}".format(time.strftime("%Y-%m-%dT%H:%M:%S%z")),
        "### git  {}".format(git_describe()),
        "",
    ]
    argv = ["make", "-C", directory, "run-" + driver, "CONFIGS=" + configs]
    if opts:
        argv.append("OPTS=" + opts)
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    lines = []
    with open(log_path, "w") as log:
        log.write("\n".join(header))
        for line in proc.stdout:
            if echo:
                sys.stdout.write(line)
            log.write(line)
            lines.append(line)
    return proc.wait(), "".join(lines)


def git_describe():
    def git(*a):
        return subprocess.run(["git", "-C", ROOT] + list(a),
                              capture_output=True, text=True).stdout.strip()
    dirty = "" if not git("status", "--porcelain") else "-dirty"
    return git("rev-parse", "--short", "HEAD") + dirty


# --- recording --------------------------------------------------------------

def enabled_extensions(directory):
    """What the build actually compiled, read back out of its own stamp --
    not what was typed on the command line."""
    stamp = os.path.join(directory, "config.stamp")
    if not os.path.exists(stamp):
        return ""
    found = re.findall(r"-DVX_CFG_EXT_((?:SYM|AUTH)[A-Z0-9_]*)_ENABLE\b",
                       open(stamp).read())
    return " ".join(sorted(set(found)))


def perf_records(output):
    """Each <APP>_PERF: line as a dict of its key=value fields."""
    return [dict(field.split("=", 1) for field in line.split())
            for line in PERF_RE.findall(output)]


def append_records(csv_path, rows):
    new = not os.path.exists(csv_path)
    if not new:
        with open(csv_path) as fh:
            header = fh.readline().strip().split(",")
        if header != COLUMNS:
            sys.exit("{} was written with different columns; appending would "
                     "misalign it.\nPoint --runs at a fresh directory."
                     .format(csv_path))
    with open(csv_path, "a", newline="\n") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS, lineterminator="\n")
        if new:
            writer.writeheader()
        writer.writerows(rows)


# --- one run -----------------------------------------------------------------

def execute(case_name, app, opts, configs, args, echo=True):
    """Build if needed, run, record. Returns (rows, note) -- note is None on a
    clean run, else why nothing was recorded."""
    try:
        directory = build_dir(args.build, app)
    except Unrunnable as why:
        return [], str(why)
    runs = args.runs or os.path.join(args.build, "crypto_runs")
    os.makedirs(os.path.join(runs, "logs"), exist_ok=True)

    slug = (opts or "default").replace(" ", "").replace("-", "_")
    name = "{}-{}-{}-{}.log".format(app, args.driver, slug,
                                    time.strftime("%Y%m%d-%H%M%S"))
    log_path = os.path.join(runs, "logs", name)
    rc, output = execute_run(directory, args.driver, opts, configs, log_path,
                             echo=echo)

    records = perf_records(output)
    if not records:
        skipped = [l for l in output.splitlines() if l.startswith("SKIPPED:")]
        return [], (skipped[0] if skipped else
                    "no <APP>_PERF: line (exit {}); see {}".format(rc, log_path))
    note = run_verdict(rc, output, records, args.expect_fail)
    if note:
        return [], "{}; see {}".format(note, log_path)

    row = {c: records[0].get(c, "") for c in COLUMNS}
    row.update(app=app, driver=args.driver, opts=opts or "",
               extensions=enabled_extensions(directory),
               git=git_describe(), configs=configs,
               log=os.path.join("logs", name))
    append_records(os.path.join(runs, "records.csv"), [row])
    return [row], None


def run_verdict(rc, output, records, expect_fail):
    """None when the run is admissible evidence, else why it is not."""
    if len(records) != 1:
        return "{} PERF lines, need exactly 1".format(len(records))
    if expect_fail:
        return None if "FAILED!" in output else "expected FAILED!, saw none"
    if rc != 0:
        return "exit {}".format(rc)
    if "PASSED!" not in output:
        return "no PASSED! line"
    return None


def resolve_configs(case_configs, shape):
    """A case's macros with any shape of its own stripped, plus the one asked
    for. Two cases with the same result share a simulator build."""
    keep = [c for c in case_configs.split()
            if not any(k in c for k in ("NUM_CORES", "NUM_WARPS", "NUM_THREADS"))]
    return " ".join(keep + shape_configs(shape))


# --- entry point -------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--case", help="one case name from the catalog")
    p.add_argument("--yaml", help="run every case in this testcases file")
    p.add_argument("--app", help="app directory name (without --case/--yaml)")
    p.add_argument("--configs", default="", help="build macros (without --case)")
    p.add_argument("--driver", default="rtlsim", choices=["rtlsim", "simx"])
    p.add_argument("--shape", default="c2w4t16",
                   help="core/warp/thread shape (default: the recorded c2w4t16)")
    p.add_argument("--runs", default=os.environ.get("RUNS"),
                   help="where logs and records go (default: <build>/crypto_runs)")
    p.add_argument("--build", default=os.path.join(ROOT, "build32"))
    p.add_argument("--list", action="store_true", help="list the cases and exit")
    p.add_argument("--expect-fail", action="store_true",
                   help="record a run that prints FAILED! -- only for the "
                        "diagnostics measured on a deliberately wrong answer")
    # The application's own options, passed straight through. A value given
    # here replaces the one the case carries; anything omitted keeps the
    # case's. Both apps take the same five.
    p.add_argument("-n", metavar="MSGS", help="messages")
    p.add_argument("-b", metavar="BLOCKS",
                   help="blocks per message -- a block is 16 bytes for "
                        "aes_gcm and 64 for chacha_poly,\nso compare the two "
                        "through bytes, never through blocks")
    p.add_argument("-t", metavar="BYTES",
                   help="tail bytes: the partial block after the last whole one")
    p.add_argument("-a", metavar="BYTES", help="AAD bytes")
    p.add_argument("-i", metavar="IMPL",
                   help="implementation index (--list shows each case's)")
    args = p.parse_args()

    cases = catalog_cases(args.yaml)

    if args.list:
        width = max(len(n) for n in cases)
        for name, case in sorted(cases.items()):
            print("  {:<{w}}  {:<24}  {}".format(
                name, case_options(case) or "(makefile default)",
                enabled_from_configs(case.configs), w=width))
        return 0

    if args.yaml:
        return run_batch(cases, args)

    if args.case:
        if args.case not in cases:
            sys.exit("unknown case {!r} -- try --list".format(args.case))
        case = cases[args.case]
        app, opts = case_app(case), split_options(case_options(case))
        configs = resolve_configs(case.configs, args.shape)
    elif args.app:
        app, opts = args.app, {}
        configs = resolve_configs(args.configs, args.shape)
    else:
        sys.exit("give --case <id>, --yaml <file>, or --app <name> --configs '...'")

    for flag in "nbtai":
        if getattr(args, flag) is not None:
            opts[flag] = getattr(args, flag)

    try:
        build_dir(args.build, app)     # fail fast, with the configure hint
    except Unrunnable as why:
        sys.exit("{}: {}".format(args.case or app, why))

    rows, note = execute(args.case, app, join_options(opts), configs, args)
    if note:
        print("\n-> NO RECORD. " + note)
        return 1
    print("-> {} record(s) recorded".format(len(rows)))
    return 0


def say(text):
    """Print and flush: a redirected stdout is block-buffered, which makes a
    long sweep look hung until it finishes."""
    print(text, flush=True)


def run_batch(cases, args):
    """Every case in the file, ordered so that cases sharing a simulator build
    run together. rtlsim re-verilates whenever CONFIGS changes -- tens of
    seconds against a few for the run itself -- so the order is the cost."""
    plan = []
    for name, case in sorted(cases.items()):
        opts = split_options(case_options(case))
        for flag in "nbtai":
            if getattr(args, flag) is not None:
                opts[flag] = getattr(args, flag)
        plan.append((resolve_configs(case.configs, args.shape), name,
                     case_app(case), join_options(opts)))
    plan.sort(key=lambda item: (item[0], item[1]))

    builds = len({configs for configs, _, _, _ in plan})
    say("{} cases, {} distinct simulator builds ({} rebuilds avoided by "
        "grouping)\n".format(len(plan), builds, len(plan) - builds))

    done, empty, current = [], [], None
    for configs, name, app, opts in plan:
        if configs != current:
            current = configs
            say("=== build: {}".format(
                enabled_from_configs(configs) or "(no crypto extensions)"))
        rows, note = execute(name, app, opts, configs, args, echo=False)
        if rows:
            done.append((name, rows[0]))
            say("  {:<30} {:>10} cycles  {:>9} instrs".format(
                name, rows[0]["cycles"], rows[0]["instrs"]))
        else:
            empty.append((name, note))
            say("  {:<30} -- {}".format(name, note))

    say("\n{} recorded, {} produced no record".format(len(done), len(empty)))
    for name, note in empty:
        say("  {:<30} {}".format(name, note))
    return 0 if done else 1


def enabled_from_configs(configs):
    """The short extension names in a catalog case's configs, for --list."""
    return " ".join(sorted(
        m for m in re.findall(r"-DVX_CFG_EXT_([A-Z0-9_]+)_ENABLE\b", configs or "")))


if __name__ == "__main__":
    sys.exit(main())
