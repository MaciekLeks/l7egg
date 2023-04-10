#!/usr/bin/env bash
set -e
kind create cluster

kubectl create secret generic regcred --from-file=.dockerconfigjson=/home/mlk/.docker/config.json --type=kubernetes.io/dockerconfigjson

kubectl apply -f k8s
