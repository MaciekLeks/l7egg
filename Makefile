.ONESHELL:
SHELL = /bin/bash

ARCH=$(shell uname -m)

CC = clang
GO = /usr/local/go/bin/go

MAIN = l7egg
GO = /usr/local/go/bin/go

TAG ?= latest
DEBUG ?= 1

BUILD_DIR = build
TARGET_STANDALONE := $(BUILD_DIR)/$(MAIN)-static
TARGET_K8S := $(BUILD_DIR)/$(MAIN)-k8s
TARGET_BPF := $(BUILD_DIR)/$(MAIN).bpf.o

LIBBPF_DIR ?= /home/mlk/dev/github/libbpfgo/output
LIBBPF_STATIC_LIB = $(LIBBPF_DIR)/libbpf.a

CMD_STANDALONE_GO_SRC := ./cmd/standalone/*.go
CMD_K8S_GO_SRC := ./cmd/kubernetes/*.go
BPF_SRC := $(wildcard ./kernel/*.c)
BPF_HEADERS := $(wildcard ./kernel/*.h)


CFLAGS = -g -O2 -Wall -fpie
LDFLAGS = $(LDFLAGS)

CGO_CFLAGS_STATIC = "-I$(abspath $(LIBBPF_DIR))"
CGO_LDFLAGS_STATIC = "-lelf -lz $(LIBBPF_STATIC_LIB)"
CGO_EXTLDFLAGS_STATIC = '-w -extldflags "-static"'

.PHONY: all
all: $(TARGET_BPF) $(TARGET_STANDALONE)


$(BPF_SRC): $(BPF_HEADERS)

$(TARGET_BPF): $(BPF_SRC)
	echo "EBPF:" >&2
	$(CC) \
		-MJ compile_commands.json \
	    -g \
	    -Wall \
	    -fpie \
		-I$(LIBBPF_DIR) \
		-D__TARGET_ARCH_$(ARCH) \
		-DDEBUG=$(DEBUG) \
		-O2 \
		-target bpf \
		-c $^ \
		-o $@

$(TARGET_STANDALONE): $(CMD_STANDALONE_GO_SRC) $(TARGET_BPF)
	echo "GO:" >&2
	CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
	CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
	$(GO) build \
	-tags netgo -ldflags $(CGO_EXTLDFLAGS_STATIC) \
	-o $(TARGET_STANDALONE) ./cmd/standalone/$(MAIN).go

.PHONY: clean
clean:
	$(GO) clean -i
	rm $(TARGET_BPF) $(TARGET_STANDALONE) $(TARGET_K8S) compile_commands.json  2> /dev/null || true

.PHONY: vmlinuxh
vmlinuxh:
	echo "vmlinuxh"
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > kernel/vmlinux.h

.PHONY: remote-build
remote-build:
	rsync -ahv --exclude '.git' --delete . mlk@ubu-ebpf:~/ebpf-tests/
	ssh mlk@ubu-ebpf "cd ~/ebpf-tests && make clean && make all"

.PHONY: remote-build
remote-build2:
	rsync -ahv  --delete --exclude '.git' . mlk@ubu-ebpf2:~/dev/ebpf-tests/
	ssh mlk@ubu-ebpf2 "cd ~/dev/ebpf-tests/build && make clean && make all"

.PHONY: docker
docker:
	cd ../
	docker build -t maciekleks/kseg:$(TAG) -f ./build/Dockerfile .
	docker push maciekleks/kseg:$(TAG)

# code-genartor must be set in the PATH variable
# Generates:
# - deepcopy objects
# - clientsets
# - informers
# - listers
K8S_CODE_GENERATOR ?= ${GOPATH}/src/github.com/k8s.io/code-generator
.PHONY: k8s-build-client
k8s-build-client:
	$(K8S_CODE_GENERATOR)/generate-groups.sh  \
	all \
	github.com/MaciekLeks/l7egg/pkg/client \
	github.com/MaciekLeks/l7egg/pkg/apis \
	"maciekleks.dev:v1alpha1" \
	--go-header-file $(K8S_CODE_GENERATOR)/hack/boilerplate.go.txt

k8s-build-cmd: $(CMD_K8S_GO_SOURCE) $(TARGET_BPF)
	CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
	GO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
	$(GO) build \
	-tags netgo -ldflags $(CGO_EXTLDFLAGS_STATIC) \
	-o $(TARGET_K8S) ./cmd/kubernetes/$(MAIN).go

K8S_CONTROLLER_GEN ?= ${GOPATH}/src/github.com/kubernetes-sigs/controller-tools/cmd/controller-gen
# before use build controller-gen in  $K8S_CONTROLLER_GEN using command `go build -o controller-gen`
.PHONY: k8s-build-crds
k8s-build-crds:
	$(K8S_CONTROLLER_GEN)/controller-gen crd \
	paths=./pkg/apis/... \
	output:crd:dir=manifests \

