#!/usr/bin/env bash
set -e

microk8s kubectl create secret generic regcred --from-file=.dockerconfigjson=/home/mlk/.docker/config.json --type=kubernetes.io/dockerconfigjson
microk8s kubectl apply -f k8s

