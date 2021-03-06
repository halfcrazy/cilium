include ../Makefile.defs

FLAGS := -Iinclude -I. -D__NR_CPUS__=$(shell nproc) -O2

CLANG_FLAGS :=  ${FLAGS} -target bpf -emit-llvm
# eBPF verifier enforces unaligned access checks where necessary, so don't
# let clang complain too early.
CLANG_FLAGS += -Wall -Werror -Wno-address-of-packed-member -Wno-unknown-warning-option
LLC_FLAGS   := -march=bpf -mcpu=probe -filetype=obj

BPF = bpf_lxc.o bpf_netdev.o bpf_overlay.o bpf_lb.o bpf_xdp.o
SCRIPTS = init.sh join_ep.sh run_probes.sh spawn_netns.sh
LIB := $(shell find ./ -name '*.h')

CLANG ?= clang
LLC   ?= llc

ifeq ("$(PKG_BUILD)","")

all: $(BPF)

%.o: %.c $(LIB)
	${CLANG} ${CLANG_FLAGS} -c $< -o $(patsubst %.o,%.ll,$@)
	${LLC} ${LLC_FLAGS} -o $@ $(patsubst %.o,%.ll,$@)

check:
	sparse -Wsparse-all ${FLAGS} *.c
	clang ${CLANG_FLAGS} --analyze *.c

LB_OPTIONS = \
	-DLB_L3 \
	-DLB_L4 \
	-DLB_L3 -DLB_L4

bpf_lb.o: bpf_lb.c $(LIB)
	$(foreach OPTS,$(LB_OPTIONS), \
		${CLANG} ${OPTS} ${CLANG_FLAGS} -c $< -o $(patsubst %.o,%.ll,$@) || exit 2; \
		${LLC} ${LLC_FLAGS} -o /dev/null $(patsubst %.o,%.ll,$@) || exit 2; )
	${CLANG} ${CLANG_FLAGS} -c $< -o $(patsubst %.o,%.ll,$@)
	${LLC} ${LLC_FLAGS} -o $@ $(patsubst %.o,%.ll,$@)

LXC_OPTIONS = \
	 -DDROP_ALL \
	 -DHAVE_LPM_MAP_TYPE \
	 -DSKIP_CIDR_LPM_MAP \
	 -DSKIP_CIDR_MAPPINGS
	# FIXME: GH-2906: Test with both SKIP_CIDR_LPM_MAP and LPM_MAP_TYPE

bpf_lxc.o: bpf_lxc.c $(LIB)
	$(foreach OPTS,$(LXC_OPTIONS), \
		${CLANG} ${OPTS} ${CLANG_FLAGS} -c $< -o $(patsubst %.o,%.ll,$@) || exit 2; \
		${LLC} ${LLC_FLAGS} -o /dev/null $(patsubst %.o,%.ll,$@) || exit 2; )
	${CLANG} ${CLANG_FLAGS} -c $< -o $(patsubst %.o,%.ll,$@)
	${LLC} ${LLC_FLAGS} -o $@ $(patsubst %.o,%.ll,$@)

else

all:

endif

install:

clean:
	rm -fr *.o
