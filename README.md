# l7egg
L7egg - Level 7 Egress Good Gateway 

L7 egress policy and shaping enforcer to use either as standalone program or K8s Operator leveraging eBPF technology. 

# Status 
It is now actively developing hence not stable yet. So, don't try this at home right now.

# Building 
Dynamically linked (recommended):
```
make dynamic
```
Dynamic linking for already installed libbpf.so:
```
LIBBPF_DIR=/usr/lib64 make dynamic 
```
Statically linked (not recommended):
```
make static
```

# Examples

## K8s
Below is one of the usage examples from the 'examples' directory:
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
    ports:
    - port: 80
      #protocol: TCP #default is TCP
    - port: 443
      protocol: TCP
    podSelector:
      matchLabels:
        app: tester
```
By default, ClusterEgg works with `cgroups`. You can change to `tc` with `spec.programType=tc`. Here we not only enforcing policy on egress traffic by specifying CIDRs, and Common Names. We also, shaping traffic applying 1mbit bandwidth.

# programType - tc or cgroups
Please find some differences between `tc` and `cgroups` program types:

| Feature                         | tc | cgroup |
|---------------------------------|:--:|:-:|
| Works with pods                 | +  | + | 
| Works with containers           | +  | + |
| Works with multi container pods | +  | + |
| Works on nodes                  | +  | - |
| Shaping                         | +  | + |
| Specifying interface name       | +  | - |

## Metrics
The metrics are available at the `:9090/metrics` endpoint of the operator POD.

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
- `crds` - Custom Resource Definitions for ClusterEgg
- `examples` - k8s example manifests
- `kernel` - eBPF kernel space C source files
- `manifests` - k8s manifests for the operator
- `pkg` - k8s operator and controller reusable GO packages
- `tools` - common tools 

# When (Status)
I'll definitely right down here _when_... Not now ;)

# "Big" TODOs (priority)
- [x] deep code refactoring
- [ ] code refactoring (logging, remove fmt.Printf/ln, etc.)
- [ ] one loaded ebpf program for many workloads 
- [x] multi container pod support
- [ ] init containers support
- [x] ipv6 support
- [x] applying Egg policy into selected PODs (in progress)
- [x] traffic shaping mechanism some features, e.g. bandwidth, ceil, burst, etc.
- [x] CRD refactoring
- [ ] tests needed :)
- [ ] ingress policies
