#!/usr/bin/env bash
# Run what CI runs, on every Python in the matrix, locally.
#
# This exists because of a specific failure. A test written to check that hpqc
# behaves well when a reader closes a pipe was itself unportable: it called
# subprocess.communicate() after handing away and closing the child's stdin,
# which raises ValueError before Python 3.12. It passed on the development
# machine, was pushed, and turned the CI red -- and the repository is private,
# so the logs were not readable from here.
#
# One Python is not a matrix. Anything that runs on four of them needs to be
# tried on four of them before it is pushed.
#
#     tools/ci-local.sh              # every version in the matrix
#     tools/ci-local.sh 3.9          # just one
#
# It needs docker (or podman aliased to it) and nothing else. The tree it tests
# is `git archive HEAD` plus whatever is staged -- never the working directory,
# so a stray file cannot make a run pass or fail on its own.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# Read out of the workflow rather than written down again: a second copy of
# the matrix would agree with the first only until one of them was edited.
VERSIONS=("$@")
if [ ${#VERSIONS[@]} -eq 0 ]; then
  mapfile -t VERSIONS < <(
    sed -n 's/^ *python-version: \[\(.*\)\]$/\1/p' .github/workflows/ci.yml \
      | tr -d '" ' | tr ',' '\n'
  )
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
git archive "$(git write-tree)" | tar -x -C "$work"

# The smoke test is extracted from the workflow rather than duplicated: two
# copies would agree only until one of them was edited.
python3 - "$work/smoke.sh" <<'PY'
import pathlib, sys
y = pathlib.Path(".github/workflows/ci.yml").read_text()
block = y.split("- name: Smoke-test the installed CLI\n", 1)[1]
lines = block.split("\n")
start = next(i for i, l in enumerate(lines) if l.strip() == "run: |") + 1
out = []
for line in lines[start:]:
    if line.strip() and not line.startswith(" " * 10):
        break
    out.append(line[10:])
pathlib.Path(sys.argv[1]).write_text("\n".join(out) + "\n")
PY

failed=()
for version in "${VERSIONS[@]}"; do
  echo "=== Python $version ==="
  # --user, and a venv under /tmp: the container writes into a directory the
  # host owns, so it must not create root-owned .pyc and egg-info files there
  # that the cleanup below then cannot remove.
  if docker run --rm \
      --user "$(id -u):$(id -g)" \
      -e HOME=/tmp -e PYTHONDONTWRITEBYTECODE=1 \
      -v "$work":/work -w /work "python:$version" bash -c '
      set -e
      python -m venv /tmp/venv
      /tmp/venv/bin/pip install --quiet --upgrade pip
      /tmp/venv/bin/pip install --quiet -e ".[dev]"
      /tmp/venv/bin/python -c "import click, cryptography; print(\"click\", click.__version__, \"| cryptography\", cryptography.__version__)"
      export PATH=/tmp/venv/bin:$PATH
      pytest -q
      bash smoke.sh < /dev/null > smoke.log 2>&1 || { tail -30 smoke.log; exit 1; }
      echo "smoke: $(grep -c ": ok$" smoke.log) checks ok"
    ' 2>&1 | grep -vE "^WARNING: (Running pip|Ignoring)|root user"
  then
    echo "--- $version: ok"
  else
    echo "--- $version: FAILED"
    failed+=("$version")
  fi
done

if [ ${#failed[@]} -ne 0 ]; then
  echo
  echo "failed on: ${failed[*]}"
  exit 1
fi
echo
echo "all of ${VERSIONS[*]} passed"
