CC=gcc

ifndef RTE_SDK
	RTE_SDK=./dpdk-2.2.0
endif

ifndef RTE_TARGET
	RTE_TARGET=x86_64-native-linuxapp-gcc
endif

DPDK_INC_DIR = ${RTE_SDK}/${RTE_TARGET}/include
DPDK_LIB_DIR = ${RTE_SDK}/${RTE_TARGET}/lib

LDFLAGS += -rdynamic -L${DPDK_LIB_DIR} -Wl,-rpath=${DPDK_LIB_DIR}
LIBS += -Wl,--whole-archive -ldpdk -Wl,--no-whole-archive -lm -lpthread \
		-ldl -lpcap -lprotobuf-c
CFLAGS += -std=gnu99 -g3 -ggdb3 -Ofast -m64 -march=native \
		  -Wall -Werror -Wno-unused-function -Wno-unused-but-set-variable \
		  -I${DPDK_INC_DIR} -D_GNU_SOURCE

.PHONY: format

pktgen: pktgen.c job.pb-c.c status.pb-c.c
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ $^ ${LIBS} 

clean:
	rm -f pktgen

format: pktgen.h pktgen.c pktgen_worker.c pktgen_util.h \
	job.pb-c.c status.pb-c.c simd.h
	clang-format -i $^
