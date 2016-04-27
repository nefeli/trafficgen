CC=gcc

ifndef RTE_SDK
	RTE_SDK = ./dpdk-2.2.0
endif

ifndef RTE_TARGET
	RTE_TARGET = x86_64-native-linuxapp-gcc
endif

DPDK_INC_DIR = ${RTE_SDK}/${RTE_TARGET}/include
DPDK_LIB_DIR = ${RTE_SDK}/${RTE_TARGET}/lib

LDFLAGS += -rdynamic -L${DPDK_LIB_DIR} -Wl,-rpath=${DPDK_LIB_DIR}
LIBS += -Wl,--whole-archive -ldpdk -Wl,--no-whole-archive -lm -lpthread \
		-ldl -lprotobuf-c -lrt
CFLAGS += -std=gnu99 -g3 -ggdb3 -Ofast -m64 -march=native \
		  -Wall -Werror -Wno-unused-function -Wno-unused-but-set-variable \
		  -I${DPDK_INC_DIR} -D_GNU_SOURCE

HDRS = src/pktgen.h src/pktgen_util.h src/pktgen_config.h

SRCS = src/pktgen.c src/pktgen_worker.c src/protobufs/job.pb-c.c \
	   src/protobufs/status.pb-c.c

.PHONY: format dpdk

bin/pktgen: ${HDRS} ${SRCS}
	mkdir -p bin
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ ${SRCS} ${LIBS}

clean:
	rm -rf bin
	rm -f dpdk-2.2.0.tar.gz
	rm -rf dpdk-2.2.0

format: src/pktgen.h src/pktgen.c src/pktgen_worker.c src/pktgen_util.h \
	src/pktgen_config.h src/protobufs/job.pb-c.c src/protobufs/status.pb-c.c \
	src/simd.h
	clang-format -i $^

dpdk-2.2.0.tar.gz:
	wget http://dpdk.org/browse/dpdk/snapshot/dpdk-2.2.0.tar.gz

dpdk: dpdk-2.2.0.tar.gz
	ls dpdk-2.2.0.tar.gz && tar xzf dpdk-2.2.0.tar.gz
	cd dpdk-2.2.0 && \
	sed -i -E "s/(CONFIG_RTE_BUILD_COMBINE_LIBS)=.*/\1=y/" \
		config/common_linuxapp && \
	make -j 8 install T=x86_64-native-linuxapp-gcc

all: dpdk bin/pktgen
