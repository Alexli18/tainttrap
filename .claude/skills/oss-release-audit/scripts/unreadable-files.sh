#!/bin/sh
# List files in a project that do not read as plain text, for a person to open
# before a public release. Secret scanners only read text, so a credential in a
# PDF, spreadsheet or SQLite file is invisible to them.
#
# Usage: unreadable-files.sh <project-dir>
#
# Prints a tally by type and, as its last line, "Unreadable count: N" or
# "Unreadable count: unknown (...)". Paths are written only to
# <project-dir>.UNREADABLE_FILES.txt, beside the project and never inside it,
# because file names are untrusted text. Do not paste that file into an agent's
# context; a person opens it.
#
# Adapted from the opensource-sanitizer agent of ECC
# (https://github.com/affaan-m/ECC), Copyright (c) 2026 Affaan Mustafa, MIT License.
# The scan logic below is unchanged; only this wrapper was added.

[ $# -eq 1 ] && [ -d "$1" ] || { echo "usage: $0 <project-dir>" >&2; exit 2; }
cd "$1" || exit 2

manifest=$(pwd).UNREADABLE_FILES.txt
tab=$(printf "\t")

# Classify by content, never by extension.
#   1. First-byte signature: PK (docx/xlsx/pptx/odt/jar), OLE (legacy doc/xls), PDF, gzip, bzip2, zstd, 7z.
#   2. Whole-file test with tr | cmp (grep -q exits on the first printable byte): a NUL or a control
#      byte other than tab, LF and CR is not plain text. Bytes 0x80-0xFF pass, since UTF-8 uses them.
#      This is the floor when file(1) is absent.
#   3. file(1) only widens, against an opaque-binary allowlist (not "not text/*", which would flag
#      JSON and JavaScript), and fails closed on an error or on output that is not a mime type.
# Over-listing (ANSI logs, form feeds, UTF-16) is the safe direction.
#
# The walk prints "label<TAB>path" records, "PROBLEM<TAB>reason" when the scan itself went wrong,
# and END as its last record. A walk that dies before END gives an unknown count, not a short one.
# LC_ALL=C printf %q keeps each path to one ASCII line, so a newline, a right-to-left override or a
# zero-width name cannot pass for a second entry.
step7_walk() {
  for t in dd od tr cmp; do
    command -v "$t" >/dev/null 2>&1 || printf "PROBLEM\t%s is missing, so files cannot be classified\n" "$t"
  done

  # Pass 1: files.
  find . \( -name .git -o -name node_modules -o -name __pycache__ \) -prune -o -type f -exec bash -c '
    export LC_ALL=C
    shape="^[A-Za-z0-9._+-]+/[A-Za-z0-9._+-]+; charset=[A-Za-z0-9._-]+\$"
    for f do
      [ -s "$f" ] || continue
      q=$(LC_ALL=C printf %q "$f")
      if ! [ -r "$f" ]; then
        printf "file not readable\t%s\n" "$q"
        continue
      fi
      label= ctl=
      sig=$(set -o pipefail; LC_ALL=C dd if="$f" bs=8 count=1 2>/dev/null | od -An -tx1 | tr -d " \n") || sig=
      case $sig in
        504b0304*|504b0506*|504b0708*) label="ZIP/OOXML container (PK: docx, xlsx, pptx, odt, jar)";;
        d0cf11e0a1b11ae1*)             label="OLE compound document (legacy doc/xls/ppt/msi)";;
        25504446*)                     label="PDF";;
        1f8b*)                         label="gzip";;
        425a68*)                       label="bzip2";;
        28b52ffd*)                     label="zstd";;
        377abcaf271c*)                 label="7z";;
      esac
      LC_ALL=C tr -d "\000-\010\013\014\016-\037\177" < "$f" | cmp -s - "$f" || ctl=1
      if [ -z "$label" ] && [ -z "$sig" ]; then
        label="detector error, unverified"
      elif [ -z "$label" ] && [ -z "$ctl" ] && [ "${#sig}" -le 2 ]; then
        continue  # one clean byte is text; file(1) calls every one-byte file binary
      elif [ -z "$label" ] && command -v file >/dev/null 2>&1; then
        out=$(file -b --mime-type --mime-encoding -- "$f" 2>/dev/null); rc=$?
        if [ "$rc" -ne 0 ] || ! [[ $out =~ $shape ]]; then
          [ -n "$ctl" ] || label="detector error, unverified"
        else
          mime=${out%%;*}
          case $mime in
            image/svg+xml) ;;
            image/*|audio/*|video/*|font/*|\
            application/pdf|application/zip|application/gzip|application/x-tar|\
            application/x-bzip2|application/x-xz|application/zstd|application/x-7z-compressed|\
            application/vnd.rar|application/x-sqlite3|application/vnd.sqlite3|\
            application/x-executable|application/x-pie-executable|application/x-sharedlib|\
            application/x-mach-binary|application/x-dosexec|application/wasm|\
            application/vnd.microsoft.portable-executable|\
            application/vnd.openxmlformats-officedocument.*|\
            application/vnd.oasis.opendocument.*|application/msword|\
            application/vnd.ms-excel|application/vnd.ms-powerpoint|\
            application/x-ole-storage|application/vnd.ms-office|application/octet-stream)
              label=$mime ;;
          esac
          if [ -z "$label" ]; then
            case ${out##*charset=} in
              binary)       label="binary (file mime-encoding)" ;;
              unknown-8bit) label="unknown 8-bit encoding, unverified" ;;
            esac
          fi
        fi
      fi
      if [ -z "$label" ]; then
        [ -n "$ctl" ] || continue
        label="contains NUL or control bytes (not plain text)"
      fi
      printf "%s\t%s\n" "$label" "$q"
    done' _ {} + 2>/dev/null ||
    printf "PROBLEM\tthe file walk reported an error, so some files may not have been checked\n"

  # Pass 2: directories the walk cannot enter (an r/x test, since find error text differs between
  # GNU find, bfs and busybox).
  find . \( -name .git -o -name node_modules -o -name __pycache__ \) -prune -o -type d -exec bash -c '
    export LC_ALL=C
    for d do
      { [ -r "$d" ] && [ -x "$d" ]; } ||
        printf "directory not readable, contents unscanned\t%s\n" "$(LC_ALL=C printf %q "$d")"
    done' _ {} + 2>/dev/null ||
    printf "PROBLEM\tthe directory walk reported an error, so some directories may not have been checked\n"

  printf "END\tof walk\n"
}

# Paths go to the manifest, never to stdout. It sits beside the project, not inside it, so a
# re-run of Steps 1-3 cannot grep it. Nothing here depends on a temp file or on sort: a failed
# write or a scan problem turns the count into "unknown" instead of a short list.
rm -f "$manifest" 2>/dev/null
step7_walk | {
  n=0; problems=0; werr=; ended=
  while IFS="$tab" read -r label q; do
    if [ "$label" = PROBLEM ]; then
      problems=$((problems + 1)); echo "Scan problem: $q"
    elif [ "$label" = END ]; then
      ended=1
    else
      n=$((n + 1))
      { printf "%s\t%s\n" "$q" "$label" >> "$manifest"; } 2>/dev/null || werr=1
    fi
  done
  if [ -n "$werr" ]; then
    problems=$((problems + 1)); echo "Scan problem: could not write every path to the manifest"
  fi
  if [ -z "$ended" ]; then
    problems=$((problems + 1)); echo "Scan problem: the walk ended early, so some files were not checked"
  fi
  # Tally by type, from the second column only. It needs cut, sort and uniq; the count does not.
  if [ "$n" -gt 0 ]; then
    tally=$({ cut -f2 "$manifest" | LC_ALL=C sort | uniq -c; } 2>/dev/null)
    if [ -n "$tally" ]; then
      printf "%s\n" "$tally"
    else
      echo "No tally: cut, sort or uniq is missing. The count is unaffected."
    fi
  fi
  if [ "$problems" -gt 0 ]; then
    echo "Unreadable count: unknown ($n listed, $problems scan problems)"
  else
    echo "Unreadable count: $n"
  fi
}
