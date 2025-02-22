# kbuild trick to avoid linker error. Can be omitted if a module is built.
obj- := dummy.o

# List of programs to build
hostprogs-y := test_verifier test_maps
hostprogs-y += sock_example
hostprogs-y += sockex1
hostprogs-y += sockex2
hostprogs-y += dropmon
hostprogs-y += ex1
hostprogs-y += ex2
hostprogs-y += ex3
hostprogs-y += simple_load

dropmon-objs := dropmon.o libbpf.o
test_verifier-objs := test_verifier.o libbpf.o
test_maps-objs := test_maps.o libbpf.o
sock_example-objs := sock_example.o libbpf.o
sockex1-objs := bpf_load.o libbpf.o sockex1_user.o
sockex2-objs := bpf_load.o libbpf.o sockex2_user.o
ex1-objs := bpf_load.o libbpf.o ex1_user.o
ex2-objs := bpf_load.o libbpf.o ex2_user.o
ex3-objs := bpf_load.o libbpf.o ex3_user.o
simple_load-objs := bpf_load.o libbpf.o simple_load.o

# Tell kbuild to always build the programs
always := $(hostprogs-y)
always += sockex1_kern.o
always += sockex2_kern.o
always += ex1_kern.o
always += ex2_kern.o
always += ex3_kern.o

HOSTCFLAGS += -I$(objtree)/usr/include

HOSTCFLAGS_bpf_load.o += -I$(objtree)/usr/include -Wno-unused-variable
HOSTLOADLIBES_sockex1 += -lelf
HOSTLOADLIBES_sockex2 += -lelf
HOSTLOADLIBES_ex1 += -lelf
HOSTLOADLIBES_ex2 += -lelf
HOSTLOADLIBES_ex3 += -lelf
HOSTLOADLIBES_simple_load += -lelf

# point this to your LLVM backend with bpf support
LLC=$(srctree)/tools/bpf/llvm/bld/Debug+Asserts/bin/llc

%.o: %.c
	clang $(NOSTDINC_FLAGS) $(LINUXINCLUDE) $(EXTRA_CFLAGS) \
		-D__KERNEL__ -Wno-unused-value -Wno-pointer-sign \
		-O2 -emit-llvm -c $< -o -| $(LLC) -filetype=obj -o $@
