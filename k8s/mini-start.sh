#!/usr/bin/env bash
set -e
#src: https://minikube.sigs.k8s.io/docs/contrib/building/iso/
# change file Dockerfile in minikube/deploy/isio/k8s-minikube/.
#~/dev/github/minikube/out/minikube -p ebpf start --disk-size=8gb --iso-url="/home/mlk/dev/github/minikube/out/minikube-amd64.iso"
#minikube -p ebpf start --driver=virtualbox --disk-size=8gb --iso-url="/home/mlk/Downloads/ubuntu-22.10-live-server-amd64.iso"
#minikube -p ebpf start --driver=docker --disk-size=8gb
rm -rf /tmp/juju-mk*
sudo minikube start --driver=none --extra-config=kubelet.resolv-conf=/run/systemd/resolve/resolv.conf
#sudo minikube start --driver=none --extra-config=kubelet.resolv-conf=/home/mlk/go/src/epbf-programming/libbpfgo-tc/k8s/resolv.conf

sleep 5
sudo kubectl create secret generic regcred --from-file=.dockerconfigjson=/home/mlk/.docker/config.json --type=kubernetes.io/dockerconfigjson

#kubectl apply -f /home/mlk/go/src/epbf-programming/libbpfgo-tc/k8s
sleep 5
sudo kubectl apply -f k8s
