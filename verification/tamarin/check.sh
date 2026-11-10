#!/usr/bin/env bash
# Runs tamarin-prover on every lemma of a model, each in a process of its own
# (one after another, so that no run holds the memory of the others), and
# compares each result with the model's expectations. tamarin-prover exits 0
# also when a lemma is falsified, the analysis is incomplete or the model is
# not well-formed, so its summary is read, not its exit code.
#
# Usage: check.sh [--all-builds] [MODEL [FLAG]]
#   MODEL         the model's file name without .spthy; without it, every
#                 model in this directory.
#   FLAG          a build: a preprocessor flag passed as -D=FLAG (a negative
#                 control), or default, the model without a flag, which is
#                 also what no FLAG means. A FLAG that MODEL.expected.tsv
#                 does not name as a build is refused.
#   --all-builds  every build of the model (or of every model): default and
#                 each build MODEL.expected.tsv names. A build whose results
#                 are not the expected ones does not stop the others; the
#                 last line lists every such build.
#   TIMEOUT       seconds per lemma (600 by default); a lemma that runs out of
#                 time is unresolved, not falsified. GNU timeout is used when
#                 on PATH; otherwise the run is killed from the shell.
#
# A lemma's result is one of verified, falsified, unresolved. MODEL.expected.tsv
# lists the expected result per build and lemma ("build<TAB>lemma<TAB>result");
# a lemma absent from the file is expected to be verified. Before any lemma is
# proved, the model and its expectations are checked against each other: each
# #ifdef names one flag, no lemma is inside an #ifdef, every result is one of
# the three, every lemma the file names is in the model, and the #ifdef flags
# are exactly the builds the file names other than default. The script exits 0
# only when they agree and every lemma's result is the one expected. Needs
# tamarin-prover and maude on PATH.
set -uo pipefail
cd "$(dirname "$0")" || exit 1
timeout_s="${TIMEOUT:-600}"

# bounded SECONDS CMD... runs CMD, killing it after SECONDS: GNU timeout when
# there is one (exit 124), otherwise a background run and a kill (exit 143).
bounded() {
	local secs="$1"
	shift
	if command -v timeout >/dev/null 2>&1; then
		timeout "$secs" "$@"
	elif command -v gtimeout >/dev/null 2>&1; then
		gtimeout "$secs" "$@"
	else
		"$@" &
		local pid=$!
		# The killer holds no copy of stdout: a caller capturing the output
		# would otherwise wait for it to finish, not for the command.
		(sleep "$secs" && kill -TERM "$pid" 2>/dev/null) >/dev/null 2>&1 </dev/null &
		local killer=$!
		wait "$pid"
		local status=$?
		kill "$killer" 2>/dev/null
		wait "$killer" 2>/dev/null
		return "$status"
	fi
}

# expected FILE BUILD LEMMA prints the expected result, verified when unlisted.
expected() {
	local want
	want=$(awk -F'\t' -v b="$2" -v l="$3" '$1 == b && $2 == l { print $3 }' "$1" 2>/dev/null | head -1)
	echo "${want:-verified}"
}

# expectation_lines FILE prints the file's expectation lines: neither a
# comment (a line starting with #) nor blank. A file with none, or no file,
# is not an error: every lemma is then expected to be verified.
expectation_lines() {
	[ -f "$1" ] || return 0
	grep -Ev '^#|^[[:space:]]*$' "$1"
	[ "$?" -le 1 ]
}

# has NAME LIST reports whether LIST, one name a line, holds NAME exactly
# (names are compared as strings, never as patterns).
has() { grep -qxF -e "$1" <<<"$2"; }

# lemmas_of MODEL.spthy, flags_of MODEL.spthy and builds_of MODEL.expected.tsv
# print one name a line. tamarin-prover reads a lemma and an #ifdef indented
# as well as at the start of the line, so these do too.
lemmas_of() { sed -nE 's/^[[:space:]]*lemma ([A-Za-z0-9_]+).*/\1/p' "$1"; }
flags_of() { sed -nE 's/^[[:space:]]*#ifdef[[:space:]]+([A-Za-z0-9_]+)[[:space:]]*$/\1/p' "$1" | sort -u; }
builds_of() { expectation_lines "$1" | cut -f1 | grep -vxF -e default | sort -u; }

# agree NAME checks NAME.spthy and NAME.expected.tsv against each other,
# prints each disagreement on a line of its own, and returns 1 when there is
# one.
agree() {
	local name="$1"
	local model="$name.spthy" expected_file="$name.expected.tsv"
	local bad=0 line lemma flag build
	while IFS= read -r line; do
		echo "check.sh: $model: #ifdef takes one flag here: $line"
		bad=1
	done < <(grep -E '^[[:space:]]*#ifdef([[:space:]]|$)' "$model" | grep -Ev '^[[:space:]]*#ifdef[[:space:]]+[A-Za-z0-9_]+[[:space:]]*$')
	if ! awk -v m="$model" '
		/^[ \t]*#ifdef/ { inside = 1; flag = $2; next }
		/^[ \t]*#endif/ { inside = 0; next }
		inside && /^[ \t]*lemma [A-Za-z0-9_]+/ {
			n = $2; sub(/[^A-Za-z0-9_].*/, "", n)
			print "check.sh: " m ": lemma " n " is inside #ifdef " flag; bad = 1
		}
		END { exit bad }' "$model"; then
		bad=1
	fi
	if ! expectation_lines "$expected_file" | awk -F'\t' -v f="$expected_file" '
		$3 != "verified" && $3 != "falsified" && $3 != "unresolved" {
			print "check.sh: " f ": " $1 " " $2 " expects " $3 ", not verified, falsified or unresolved"; bad = 1
		}
		END { exit bad }'; then
		bad=1
	fi
	local lemmas flags builds
	lemmas=$(lemmas_of "$model")
	flags=$(flags_of "$model")
	builds=$(builds_of "$expected_file")
	for lemma in $(expectation_lines "$expected_file" | cut -f2 | sort -u); do
		if ! has "$lemma" "$lemmas"; then
			echo "check.sh: $lemma is in $expected_file but is not a lemma of $model"
			bad=1
		fi
	done
	for flag in $flags; do
		if ! has "$flag" "$builds"; then
			echo "check.sh: $flag is an #ifdef of $model but not a build in $expected_file"
			bad=1
		fi
	done
	for build in $builds; do
		if ! has "$build" "$flags"; then
			echo "check.sh: $build is a build in $expected_file but not an #ifdef of $model"
			bad=1
		fi
	done
	return "$bad"
}

# prove NAME FLAG checks every lemma of NAME.spthy in one build (FLAG empty
# for default) and returns 1 when any result is not the expected one.
prove() {
	local name="$1" flag="$2"
	local model="$name.spthy" expected_file="$name.expected.tsv"
	local build="${flag:-default}"
	local lemmas
	lemmas=$(lemmas_of "$model")
	if [ -z "$lemmas" ]; then
		echo "check.sh: no lemma in $model"
		return 1
	fi
	local args=()
	[ -n "$flag" ] && args+=("-D=$flag")
	local mismatch="" n_verified=0 n_falsified=0 n_unresolved=0
	local lemma start out status summary result want
	for lemma in $lemmas; do
		start=$(date +%s)
		# ${args[@]+...}: an empty array is "unbound" to bash 3.2 under set -u.
		out=$(bounded "$timeout_s" tamarin-prover ${args[@]+"${args[@]}"} --prove="$lemma" --derivcheck-timeout=600 "$model" 2>&1)
		status=$?
		# The summary lists every lemma; only this one's line is the result
		# (the others read "analysis incomplete", not proven in this run).
		summary=$(grep -E "^[[:space:]]*$lemma \((all-traces|exists-trace)\):" <<<"$out" | head -1 | sed -E 's/^[[:space:]]+//')
		if [ "$status" -eq 124 ] || [ "$status" -eq 143 ]; then
			result=unresolved
			summary="$lemma: timed out after ${timeout_s} s"
		elif grep -iq 'wellformedness check failed' <<<"$out"; then
			result=unresolved
			summary="$lemma: wellformedness check failed"
		elif grep -Eq "^[[:space:]]*$lemma \((all-traces|exists-trace)\): verified" <<<"$out"; then
			result=verified
		elif grep -Eq "^[[:space:]]*$lemma \((all-traces|exists-trace)\): falsified" <<<"$out"; then
			result=falsified
		else
			result=unresolved
		fi
		case "$result" in
			verified) n_verified=$((n_verified + 1));;
			falsified) n_falsified=$((n_falsified + 1));;
			unresolved) n_unresolved=$((n_unresolved + 1));;
		esac
		want=$(expected "$expected_file" "$build" "$lemma")
		echo "${summary:-$lemma: no result} -> $result, expected $want ($(($(date +%s) - start)) s)"
		if [ "$result" != "$want" ]; then
			echo "$out"
			echo "check.sh: $lemma: $result, expected $want (tamarin-prover exited with $status)"
			mismatch="$mismatch $lemma"
		fi
	done
	echo "check.sh [$name/$build]: verified $n_verified, falsified $n_falsified, unresolved $n_unresolved"
	if [ -n "$mismatch" ]; then
		echo "check.sh [$name/$build]: mismatch:$mismatch"
		return 1
	fi
	echo "check.sh [$name/$build]: every lemma has its expected result"
}

# check_model NAME FLAG checks NAME in one build: its model and expectations
# agree, FLAG is a build, and every lemma has its expected result.
check_model() {
	local name="$1" flag="$2"
	[ "$flag" = default ] && flag=""
	if [ ! -f "$name.spthy" ]; then
		echo "check.sh: no model $name.spthy"
		return 1
	fi
	agree "$name" || return 1
	# tamarin-prover ignores a -D flag the model does not use and checks the
	# default model, so a misspelled FLAG would pass as a build in which every
	# lemma holds. A FLAG is a build only when the expectations name it.
	if [ -n "$flag" ] && ! has "$flag" "$(builds_of "$name.expected.tsv")"; then
		echo "check.sh: $flag is not a build in $name.expected.tsv"
		return 1
	fi
	prove "$name" "$flag"
}

# models prints the name of every model here, or nothing.
models() {
	local model
	for model in *.spthy; do
		[ -f "$model" ] && echo "${model%.spthy}"
	done
}

if [ "${1:-}" = "--all-builds" ]; then
	shift
	if [ "$#" -gt 1 ]; then
		echo "check.sh: --all-builds takes no FLAG"
		exit 1
	fi
	names=${1:-$(models)}
	if [ -z "$names" ]; then
		echo "check.sh: no model in $(pwd)"
		exit 1
	fi
	failed=""
	for name in $names; do
		if [ ! -f "$name.spthy" ]; then
			echo "check.sh: no model $name.spthy"
			failed="$failed $name/default"
			continue
		fi
		builds="default $(builds_of "$name.expected.tsv" | tr '\n' ' ')"
		if ! agree "$name"; then
			for build in $builds; do failed="$failed $name/$build"; done
			continue
		fi
		for build in $builds; do
			flag=$build
			[ "$flag" = default ] && flag=""
			prove "$name" "$flag" || failed="$failed $name/$build"
		done
	done
	if [ -n "$failed" ]; then
		echo "check.sh: builds with a mismatch:$failed"
		exit 1
	fi
	echo "check.sh: every build has its expected result"
	exit 0
fi

if [ "$#" -gt 0 ]; then
	check_model "$1" "${2:-}"
	exit $?
fi
names=$(models)
if [ -z "$names" ]; then
	echo "check.sh: no model in $(pwd)"
	exit 1
fi
failed=""
for name in $names; do
	check_model "$name" "" || failed="$failed $name"
done
if [ -n "$failed" ]; then
	echo "check.sh: models with a mismatch:$failed"
	exit 1
fi
