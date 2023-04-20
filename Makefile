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
TARGET_CLI := $(BUILD_DIR)/$(MAIN)-cli
TARGET_K8S_STATIC := $(BUILD_DIR)/$(MAIN)-k8s-static
TARGET_K8S_DYN := $(BUILD_DIR)/$(MAIN)-k8s-dynamic
TARGET_BPF := $(BUILD_DIR)/$(MAIN).bpf.o

# clone https://github.com/libbpf/libbpf
# then, go to src dir and run e.g.
# OBJDIR=build DESTDIR=root make install
LIBBPF_DIR ?= /home/mlk/dev/github/libbpf/src/root/usr
LIBBPF_STATIC_LIB = $(LIBBPF_DIR)/lib64/libbpf.a
LIBBPF_INCLUDES = $(LIBBPF_DIR)/include
LIBBPF_DYN_LIB = $(LIBBPF_DIR)/lib64

CMD_CLI_GO_SRC := ./cmd/cli/*.go
CMD_K8S_GO_SRC := ./cmd/kubernetes/*.go
BPF_SRC := $(wildcard ./kernel/*.c)
BPF_HEADERS := $(wildcard ./kernel/*.h)


CFLAGS = -g -O2 -Wall -fpie
LDFLAGS = $(LDFLAGS)

CGO_CFLAGS = "-I$(abspath $(LIBBPF_INCLUDES))"
CGO_LDFLAGS_STATIC = "-lelf -lz $(LIBBPF_STATIC_LIB)"
#CGO_EXTLDFLAGS_STATIC = '-w -extldflags "-static"'
# librabbry order is important for GO_EXTLDFLAGS_STATIC:
GO_EXTLDFLAGS_STATIC = '-w -extldflags "-static $(LIBBPF_STATIC_LIB) -lelf -lz"'

# inject shared library search path into the executable: -Wl,rpath=...:
GO_EXTLDFLAGS_DYN = '-w -extldflags "-lelf -lz  -Wl,-rpath=$(LIBBPF_DYN_LIB) -L$(LIBBPF_DYN_LIB) -lbpf"'

.PHONY: all
all: $(TARGET_BPF) $(TARGET_CLI)


$(BPF_SRC): $(BPF_HEADERS)

$(TARGET_BPF): $(BPF_SRC)
	echo "EBPF:" >&2
	$(CC) \
		-MJ compile_commands.json \
	    -g \
	    -Wall \
	    -fpie \
		-I$(LIBBPF_INCLUDES) \
		-D__TARGET_ARCH_$(ARCH) \
		-DDEBUG=$(DEBUG) \
		-O2 \
		-target bpf \
		-c $^ \
		-o $@

$(TARGET_CLI): $(CMD_CLI_GO_SRC) $(TARGET_BPF)
	echo "GO:" >&2
	CGO_CFLAGS=$(CGO_CFLAGS) \
	$(GO) build -x \
	-tags netgo -ldflags $(GO_EXTLDFLAGS_STATIC) \
	-o $(TARGET_CLI) ./cmd/cli/$(MAIN).go

.PHONY: clean
clean:
	$(GO) clean -i
	rm $(TARGET_BPF) $(TARGET_CLI) $(TARGET_K8S_STATIC) $(TARGET_K8S_DYN) compile_commands.json  2> /dev/null || true

.PHONY: vmlinuxh
vmlinuxh:
	echo "vmlinuxh"
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./kernel/vmlinux.h

.PHONY: remote-build
remote-build:
	rsync -ahv --exclude '.git' --delete . mlk@ubu-ebpf:~/ebpf-tests/
	ssh mlk@ubu-ebpf "cd ~/dev/ebpf-tests && make clean && make all"

.PHONY: remote-build
remote-build2:
	rsync -ahv  --delete --exclude '.git' . mlk@ubu-ebpf2:~/dev/ebpf-tests/
	ssh mlk@ubu-ebpf2 "cd ~/dev/ebpf-tests && make clean && make all"

.PHONY: docker
docker:
	cd ../
	docker build -t maciekleks/kseg:$(TAG) -f ./build/Dockerfile .
	docker push maciekleks/kseg:$(TAG)

# code-genartor must be set in the K8S_CODE_GENERATOR
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

k8s-build-cmd-static: $(CMD_K8S_GO_SOURCE) $(TARGET_BPF)
	CGO_CFLAGS=$(CGO_CFLAGS) \
	$(GO) build -x \
	-tags netgo -ldflags $(GO_EXTLDFLAGS_STATIC) \
	-o $(TARGET_K8S_STATIC) ./cmd/kubernetes/$(MAIN).go

k8s-build-cmd-dynamic: $(CMD_K8S_GO_SOURCE) $(TARGET_BPF)
	CGO_CFLAGS=$(CGO_CFLAGS) \
	$(GO) build -x \
	-tags netgo -ldflags $(GO_EXTLDFLAGS_DYN) \
	-o $(TARGET_K8S_DYN) ./cmd/kubernetes/$(MAIN).go

#CGO_LDFLAGS=$(CGO_LDFLAGS_DYNAMIC) \

K8S_CONTROLLER_GEN ?= ${GOPATH}/src/github.com/kubernetes-sigs/controller-tools/cmd/controller-gen
# before use build controller-gen in  $K8S_CONTROLLER_GEN using command `go build -o controller-gen`
.PHONY: k8s-build-crds
k8s-build-crds:
	$(K8S_CONTROLLER_GEN)/controller-gen crd \
	paths=./pkg/apis/... \
	output:crd:dir=manifests \

#tools/tc-cleaner: tools/tc-cleaner.go
#	$(GO) build -o $@ $<