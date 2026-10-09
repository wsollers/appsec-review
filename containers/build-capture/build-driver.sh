#!/bin/sh
set -eu
capture_root=$1
string_limit=$2
call_limit=$3
stream_limit=$4
wrapper_root=$5
capture_envp=$6
shift 6
export APPSEC_CAPTURE_ROOT="$capture_root"
export APPSEC_CAPTURE_CALL_LIMIT="$call_limit"
export APPSEC_CAPTURE_STREAM_LIMIT="$stream_limit"
export APPSEC_CAPTURE_REAL_PATH="$PATH"
export APPSEC_CAPTURE_ENVP="$capture_envp"
APPSEC_CAPTURE_PYTHON=$(command -v python3)
export APPSEC_CAPTURE_PYTHON
export PATH="$wrapper_root:$PATH"
if [ "$capture_envp" = "1" ]; then
  exec strace -ff -qq -ttt -v -s "$string_limit" \
    -e trace=clone,clone3,fork,vfork,execve,execveat,exit,exit_group,openat,openat2,connect \
    -o "$capture_root/trace" -- "$@"
fi
exec strace -ff -qq -ttt -s "$string_limit" \
  -e trace=clone,clone3,fork,vfork,execve,execveat,exit,exit_group,openat,openat2,connect \
  -o "$capture_root/trace" -- "$@"
