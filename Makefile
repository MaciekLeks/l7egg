ARCH=$(shell uname -m)

CLANG = clang
GO = /usr/local/go/bin/go
CC = gcc
MAIN = main

TAG ?= latest
DEBUG ?= 1

TARGET := main
TARGET_BPF := $(TARGET).bpf.o

LIBBPF ?= /home/mlk/dev/github/libbpfgo/output


CMD_STANDALONE_GO_SRC := ./cmd/standalone/*.go
CMD_K8S_GO_SRC := ./cmd/kubernetes/*.go
BPF_SRC := $(wildcard *.bpf.c)
BPF_HEADERS := $(wildcard *.h)

#on ubu-ebpf only
# structure there:
# ~/ebpf-tests (you are here!)
# ~/libbpfgo (you need this project whole code), so clone libbpfgo there first
#LIBBPF_SRC = $(abspath /home/mlk/dev/github/libbpfgo/libbpf/src)
LIBBPF_OBJ = $(LIBBPF)/libbpf.a

CFLAGS = -g -O2 -Wall -fpie
LDFLAGS =

CGO_CFLAGS_STATIC = "-I$(abspath $(LIBBPF))"
CGO_LDFLAGS_STATIC = "-lelf -lz $(LIBBPF_OBJ)"
CGO_EXTLDFLAGS_STATIC = '-w -extldflags "-static"'

.PHONY: all
all: $(TARGET_BPF) $(TARGET)

$(TARGET): $(CMD_STANDALONE_GO_SRC)
	echo "GO:" >&2
	CC=$(CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
		$(GO) build \
		-tags netgo -ldflags $(CGO_EXTLDFLAGS_STATIC) \
		-o $(MAIN)-static ./cmd/standalone/$(MAIN).go

$(BPF_SRC): $(BPF_HEADERS)

$(TARGET_BPF): $(BPF_SRC)
	echo "EBPF:" >&2
	clang \
		-MJ compile_commands.json \
	    -g \
	    -Wall \
	    -fpie \
		-I$(LIBBPF) \
		-D__TARGET_ARCH_$(ARCH) \
		-DDEBUG=$(DEBUG) \
		-O2 \
		-target bpf \
		-c $^ \
		-o $@

.PHONY: clean
clean:
	$(GO) clean -i
	rm $(TARGET_BPF)  2> /dev/null || true

.PHONY: vmlinuxh
vmlinuxh:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: remote-build
remote-build:
	rsync -ahv --exclude '.git' --delete ./ mlk@ubu-ebpf:~/ebpf-tests/
	ssh mlk@ubu-ebpf "cd ~/ebpf-tests && make clean && make all"

.PHONY: remote-build
remote-build2:
	rsync -ahv  --delete --exclude '.git' ./ mlk@ubu-ebpf2:~/dev/ebpf-tests/
	ssh mlk@ubu-ebpf2 "cd ~/dev/ebpf-tests && make clean && make all"

.PHONY: docker
docker:
	docker build -t maciekleks/kseg:$(TAG) .
	docker push maciekleks/kseg:$(TAG)

# code-genartor must be set in the PATH variable
K8S_CODE_GENERATOR ?= ${GOPATH}/src/github.com/k8s.io/code-generator
.PHONY: k8s-generate-groups
k8s-generate-groups:
	$(K8S_CODE_GENERATOR)/generate-groups.sh  \
	all \
	github.com/MaciekLeks/l7egg/pkg/client \
	github.com/MaciekLeks/l7egg/pkg/apis \
	"maciekleks.dev:v1alpha1" \
	--go-header-file $(K8S_CODE_GENERATOR)/hack/boilerplate.go.txt

k8s-build-cmd: $(CMD_K8S_GO_SOURCE)
	CC=$(CLANG) \
	CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
	GO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
	$(GO) build \
	-tags netgo -ldflags $(CGO_EXTLDFLAGS_STATIC) \
	-o $(MAIN)-k8s ./cmd/kubernetes/$(MAIN).go