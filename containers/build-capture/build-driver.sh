#!/bin/sh
set -eu
capture_root=$1
string_limit=$2
call_limit=$3
wrapper_root=$4
capture_envp=$5
shift 5
export APPSEC_CAPTURE_ROOT="$capture_root"
export APPSEC_CAPTURE_CALL_LIMIT="$call_limit"
export APPSEC_CAPTURE_REAL_PATH="$PATH"
export APPSEC_CAPTURE_ENVP="$capture_envp"
APPSEC_CAPTURE_PYTHON=$(command -v python3)
export APPSEC_CAPTURE_PYTHON
export PATH="$wrapper_root:$PATH"
# Keep compiler-created response files and other temporary provenance inputs on the
# run-owned workspace bind.  A fresh directory avoids trusting a target-provided path and
# survives until the host snapshots response files after strace exits.
umask 077
scratch_root=$(mktemp -d "$PWD/.appsec-review-build-scratch.XXXXXX")
export TMPDIR="$scratch_root"
export TMP="$scratch_root"
export TEMP="$scratch_root"
# MSBuild normally deletes ToolTask response files before post-build capture can bind them.
# Its documented diagnostic switch keeps those bounded scratch inputs available for snapshotting.
export MSBUILDPRESERVETOOLTEMPFILES=1
if [ "$capture_envp" = "1" ]; then
  exec strace --seccomp-bpf -ff -qq -y -ttt -v -s "$string_limit" \
    -e trace=clone,clone3,fork,vfork,execve,execveat,exit,exit_group,open,openat,openat2,creat,chdir,fchdir,rename,renameat,renameat2,link,linkat,unlink,unlinkat,connect \
    -o "$capture_root/trace" -- "$@"
fi
exec strace --seccomp-bpf -ff -qq -y -ttt -s "$string_limit" \
  -e trace=clone,clone3,fork,vfork,execve,execveat,exit,exit_group,open,openat,openat2,creat,chdir,fchdir,rename,renameat,renameat2,link,linkat,unlink,unlinkat,connect \
  -o "$capture_root/trace" -- "$@"
