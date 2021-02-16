#!/bin/bash
# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

# Assume script is located under tools/testing/selftests/bpf/. We want to start
# build attempts from the top of kernel repository.
SCRIPT_REL_PATH=$(realpath --relative-to=$PWD $0)
SCRIPT_REL_DIR=$(dirname $SCRIPT_REL_PATH)
KDIR_ROOT_DIR=$(realpath $PWD/$SCRIPT_REL_DIR/../../../../)
cd $KDIR_ROOT_DIR

for target in docs-install docs-uninstall; do
	RST2MAN_OPTS="--exit-status=1"					\
	prefix= DESTDIR=${PWD}/${SCRIPT_REL_DIR}/tools			\
	make -s -C tools/bpf -f Makefile.docs $* $target
done
