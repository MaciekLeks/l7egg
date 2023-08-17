# l7egg
L7egg - Level 7 Egress Good Gateway 

L7 egress policy and shaping enforcer to use either as standalone program or K8s Operator. 

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

## K8s
Sample example from the `examples` directory:
```yml
apiVersion: maciekleks.dev/v1alpha1
kind: ClusterEgg
metadata:
  name: clusteregg-pod-example-cgroup
spec:
  #programType: cgroup #default
  ingress: {}
  egress:
    shaping:
      rate: 1mbit
      ceil: 1mbit
    commonNames:
    - www.interia.pl
    - cluster.local
    cidrs:
    - 10.152.183.0/24
    - 169.254.1.1/32
    - 192.168.57.0/24
    podSelector:
      matchLabels:
        app: tester
```
By default, ClusterEgg works with `cgroups`. You can change to `tc` with `spec.programType=tc`. Here we not only policying egress traffic by specifing CIDRs, and Common Names. We also, shaping traffic here applying 1mbit bandwidth.

# programType - tc or cgroups
Please find some differences between `tc` and `cgroups` program types:

| Feature                         | tc | cgroup |
|---------------------------------|:--:| :-: |
| Works with pods                 | +  | + | 
| Works with containers           | +  | + |
| Works with multi container pods | +  | - |
| Works on nodes                  | +  | - |
| Shaping                         | +  | + |



## CLI:
TODO: add accurate example
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

### Troubleshooting
#### l7egg-static does not restart
Traffic Control qdisc and filters cleansing is needed first:
```bash
./tools/tc-cleaner.sh -iface=${iface} -eface=${eface}
```
and run the command again.


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
