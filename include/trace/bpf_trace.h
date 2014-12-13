/* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _LINUX_KERNEL_BPF_TRACE_H
#define _LINUX_KERNEL_BPF_TRACE_H

struct bpf_func_proto;
enum bpf_func_id;

/* For tracing filters save first six arguments of tracepoint events.
 * argN fields match one to one to arguments passed to tracepoint events.
 */
struct bpf_context {
	u64 arg1;
	u64 arg2;
	u64 arg3;
	u64 arg4;
	u64 arg5;
	u64 arg6;
	u64 ret;
};

const struct bpf_func_proto *tracing_filter_func_proto(enum bpf_func_id);

#endif /* _LINUX_KERNEL_BPF_TRACE_H */
