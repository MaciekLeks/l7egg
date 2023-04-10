#!/bin/bash

# clsact is superset over ingress and egress
#ingress on lo
# after applying main-static (code adds clsact class into ingress - default ffff:)
#sudo tc qdisc show dev lo
#qdisc ingress (ffff:) <default
#qdisc clsact where ffff: is parent

#egress on enp0s3



set +e
echo "--- before del"
sudo tc filter show dev lo ingress
sudo tc filter show dev enp0s3 egress
echo "--- Cleaning"
#sudo tc qdisc del dev enp0s3 root
##sudo tc qdisc del dev enp0s3 clsact
sudo tc filter del dev enp0s3 egress
#sudo tc qdisc del dev lo ingress
##sudo tc qdisc del dev lo clsact
sudo tc filter del dev lo ingress

echo "-- Shaping"
#sudo tc qdisc add dev enp0s3 root handle 1:0 htb default 30
#sudo tc class add dev enp0s3 parent 1:0 classid 1:10 htb rate 100mbit
#sudo tc qdisc add dev lo ingress
#sudo tc class add dev lo parent 1:0 classid 1:10 htb rate 100mbit

echo "-- Stats"
sudo tc qdisc show
sudo tc class show dev enp0s3
sudo bpftool net list
