.DEFAULT_GOAL := all

.PHONY: all
all: bess
	./bess/build.py --plugin ${PWD}

.PHONY: bess
bess:
	[ -e bess/.git ] || git submodule update --init
