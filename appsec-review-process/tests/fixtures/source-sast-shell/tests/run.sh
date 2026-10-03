#!/bin/sh
# Shell fixture (P14): unquoted expansion, eval of input, and a style note.
set -e
srcdir=$1
for f in `ls $srcdir/*.c`; do
  echo $f
done
eval "$2"
exit 0
