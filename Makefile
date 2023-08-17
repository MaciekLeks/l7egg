.ONESHELL:
SHELL = /bin/bash

ARCH=$(shell uname -m)

CC = clang
GO = /usr/local/go/bin/go

MAIN = l7egg
GO = /usr/local/go/bin/go

TAG ?= latest
BASE_TAG ?= latest
DEBUG ?= 1

#BUILD_DIR = build #commented for debug purposes
BUILD_DIR = .
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
# -w - removed (reason: https://youtrack.jetbrains.com/issue/GO-15231/Remote-debugging-breakpoint-not-reachable-could-not-find-file)
GO_EXTLDFLAGS_DYN = '-extldflags "-lelf -lz  -Wl,-rpath=$(LIBBPF_DYN_LIB) -L$(LIBBPF_DYN_LIB) -lbpf"'


.PHONY: all
#all: $(TARGET_BPF) $(TARGET_CLI) $(TARGET_K8S_STATIC)
all: $(TARGET_BPF) $(TARGET_CLI) $(TARGET_K8S_DYN)


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
	CGO_CFLAGS=$(CGO_CFLAGS) $(GO) build \
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


.PHONY: remote-build2
remote-build2:
	rsync -ahv  --delete --exclude '.git' . mlk@ubu-ebpf2:/home/mlk/go/src/github.com/MaciekLeks/l7egg
	ssh mlk@ubu-ebpf2 "cd /home/mlk/go/src/github.com/MaciekLeks/l7egg && make clean && make all"

.PHONY: remote-build3
remote-build3:
	rsync -ahv  --delete --exclude '.git' . mlk@ubu-ebpf3:~/dev/ebpf-tests/
	ssh mlk@ubu-ebpf3 "cd ~/dev/ebpf-tests && make clean && make all"

.PHONY: remote-build-all
remote-build-all: remote-build2 remote-build3

.PHONY: docker
docker:
	docker build -t maciekleks/l7egg-base:latest -t maciekleks/l7egg-base:$(TAG) -f Dockerfile-base .
	docker push maciekleks/l7egg-base --all-tags
	docker build -t maciekleks/l7egg:debug-$(TAG) -f Dockerfile-debug .
	docker push  maciekleks/l7egg:debug-$(TAG)
	docker build --no-cache --build-arg BASE_TAG=$(TAG) -t maciekleks/l7egg:distroless-$(TAG) -f Dockerfile-distroless .
	docker push  maciekleks/l7egg:distroless-$(TAG)
#
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

#-gcflags "all=-N -l" - debug only
$(TARGET_K8S_STATIC): $(CMD_K8S_GO_SOURCE) $(TARGET_BPF)
	CC=$(CC); CGO_ENABLED=1; CGO_CFLAGS=$(CGO_CFLAGS) \
	$(GO) build \
	-trimpath \
	-tags netgo -ldflags $(GO_EXTLDFLAGS_STATIC) \
	-gcflags "all=-N -l" \
	-o $(TARGET_K8S_STATIC) ./cmd/kubernetes/$(MAIN).go

$(TARGET_K8S_DYN): $(CMD_K8S_GO_SOURCE) $(TARGET_BPF)
	CC=$(CC); CGO_ENABLED=1; CGO_CFLAGS=$(CGO_CFLAGS) \
	$(GO) build \
	-tags netgo -ldflags $(GO_EXTLDFLAGS_DYN) \
	-gcflags "all=-N -l" \
	-o $(TARGET_K8S_DYN) ./cmd/kubernetes/$(MAIN).go

.PHONY: k8s-build-cmd-dynamic
k8s-build-cmd-dynamic: $(TARGET_K8S_DYN)

#CGO_LDFLAGS=$(CGO_LDFLAGS_DYNAMIC) \

# K8S_CONTROLLER_GEN ?= ${GOPATH}/src/github.com/kubernetes-sigs/controller-tools/cmd/controller-gen
# before use build controller-gen in  $K8S_CONTROLLER_GEN using command `go build -o controller-gen`
# see files in tools: {tools.go, generate.go}
.PHONY: k8s-build-crds
k8s-build-crds:
	$(GO) generate ./...
	#$(K8S_CONTROLLER_GEN)/controller-gen crd \
	#paths=./pkg/apis/... \
	#output:crd:dir=manifests \

#tools/tc-cleaner: tools/tc-cleaner.go
#	$(GO) build -o $@ $<