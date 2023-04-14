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
```bash
./l7egg-static -iface=enp0s3 -eface=enp0s3 -cidr=10.0.2.0/24  -cidr=10.1.0.0/16 -cidr=10.152.183.0/24 \
-cn="www.some-example.com" -cn=".ubuntu.com" -cn="api.snapcraft.io" -cn="git.com.org" -cn="docker.io"
```
## K8s
TODO:

# How
TODO

# When 
TODO