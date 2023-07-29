# l7egg
L7egg - Level 7 Egress Good Gateway 

Simple L7 egress firewall for use either as standalone program or K8s Operator. 

# Status 
It is now actively developing hence not stable yet. So, don't try this at home right now.

# Building 
## Prerequisites
You need static or shared libpf installed. 
1. Clone [libpf](https://github.com/libbpf/libbpf) upstream
2. Build your static `libbpf.a` and shared `libbpf.so`, e.g.
```bash
cd src
mkdir build
sudo OBJDIR=build DESTDIR=/ make install
```
, then 
from your root directory you can find outcomes here:
```
/usr/includes
/usr/lib64
```

## CLI:
```
make clean
LIBBPF_DIR=/ make all
```
## K8s operator/controller:
```
make clean
LIBBPF_DIR=/ make k8s-build-cmd
```

# Examples
## CLI:
To allow only egress traffic on the declared CIDRs and CNs (works with partial domain names):
```bash
sudo ./l7egg-cli -iface=enp0s3 -eface=enp0s3 \
  -cidr=10.0.2.0/24 \
  -cidr=10.1.0.0/16 \
  -cidr=18.244.102.124/32 \
  -cn="www.some-example.com" \
  -cn=".ubuntu.com" \ 
  -cn="api.snapcraft.io" \
  -cn=".gitlab.com" \
  -cm="ome.com" \
  -cn="docker.io"
```
where

`iface` - ingress network interface on which DNS responses come in the network namespace

`eface` - egress network interface that controls egress traffic

For the given example allowed egress Domain Names are (except the full domain names), e.g.:
- `www.gitlab.com`
- `api.gitlab.com`
- `ome.com`
- `home.com`
- `www.home.com`
- `www.rome.com`

# Troubleshooting
## l7egg-static does not restart
Traffic Control qdisc and filters cleansing is needed first:
```bash
./tools/tc-cleaner.sh -iface=${iface} -eface=${eface}
```
and run the command again.
## K8s
TODO:

# Project structure
- `build` - executable and object files
- `cmd` - GO commands source files
- `examples` - k8s example manifests
- `kernel` - eBPF kernel space C source files
- `manifests` - k8s CRDs manifests
- `pkg` - k8s operator and controller reusable GO packages
- `tools` - common tools 
- `user` - eBPF user space GO source files

# When (Status)
I'll definitely right down here _when_... Not now ;)

# "Big" TODOs (priority)
- [ ] code refactoring
- [ ] multi container pod support
- [x] ipv6 support
- [x] applying Egg policy into selected PODs (in progress)
- [x] traffic shaping mechanism
- [x] CRD refactoring
- [ ] tests needed :)
- [ ] ingress policies
