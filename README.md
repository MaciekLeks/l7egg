L7egg - Level 7 Egress Good Gateway 

Simple L7 egress firewall for use either as standalone program or K8s Operator. 

# Building 
## Standalone:
```
make clean
make all
```
K8s operator/controller:
```
make clean
make k8s-build-cmd
```

# Use
## Standalone:
To allow only egress traffic on the declared CIDRs and CNs (works with partial domain names):
```bash
./l7egg-static -iface=enp0s3 -eface=enp0s3 \
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

## K8s
TODO:

# How
TODO

# When 
TODO