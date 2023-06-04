FROM ubuntu:kinetic

RUN apt-get update  \
   && apt-get -y install git make clang llvm pkgconf build-essential libelf-dev curl \
   && apt-get -y install iproute2 vim util-linux wget \
   && DEBIAN_FRONTEND=noninteractive apt-get -y install tshark

# dog only
RUN wget -qO - https://azlux.fr/repo.gpg.key | apt-key add - \
    && echo "deb http://packages.azlux.fr/debian/ stable main" | tee /etc/apt/sources.list.d/azlux.list \
    && apt-get update \
    && apt-get -y install dog
#   && apt-get -y install rsync linux-source-$KRELEASE linux-headers-amd64 \
#   && rm -rf /var/lib/apt/lists/* \
#   && cd /usr/src && tar xf linux-source-$KRELEASE.tar.xz \
#   && apt-get purge -y linux-source-$KRELEASE
#
#WORKDIR /usr/src/linux-source-$KRELEASE
#RUN make olddefconfig && make headers_install

WORKDIR /tmp
RUN curl -LO https://go.dev/dl/go1.20.2.linux-amd64.tar.gz \
  && rm -rf /usr/local/go && tar -C /usr/local -xzf go1.20.2.linux-amd64.tar.gz \
  && ln -s /usr/local/go/bin/go /usr/local/bin/go

# debian only: we need bpftool >= 7 not 5
WORKDIR /kseg/hacks
RUN git clone --depth 1 --recurse-submodules https://github.com/libbpf/bpftool.git \
    && cd bpftool/src \
    && make install

WORKDIR /kseg/lib
RUN git clone --depth 1 --recurse-submodules https://github.com/aquasecurity/libbpfgo.git \
    && cd libbpfgo/libbpf/src \
    && mkdir build \
    && OBJDIR=build DESTDIR=/ make install \
    && ls -la /usr/include/bpf
    # Clones the linux kernel repo and use the latest linux kernel source BPF headers
#RUN git clone --depth 1 git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git && \
#    cp linux/include/uapi/linux/bpf* /usr/include/linux/

WORKDIR /kseg
COPY . .
RUN echo "linux-kernel:$(uname -r) bpftool:$(bpftool version)" \
    && make vmlinuxh \
    && make all DEBUG=1 LIBBPF_DIR=/usr \

ENTRYPOINT ["./build/l7egg-static"]
CMD ["-iface=eth0"]