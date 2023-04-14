#!/bin/bash

echo "Traffic Control cleansing tool for clsact qdisc used by l7egg"

iface_flag=$1
eface_flag=$2
help='Usage: tc-cleaner -iface=${iface} -eface={$eface}'

if [[ -z "$iface_flag" || ! "$iface_flag" =~ ^-iface=.+ ]]
then
  echo "Missing or wrong -iface flag."
  err=1
fi

if [[ -z "$eface_flag" || ! "$eface_flag" =~ ^-eface=.+ ]]
then
  echo "Missing or wrong -eface flag."
  err=1
fi

if [ -n "$err" ]
then
  echo "$help"
  exit 0
fi

iface=${iface_flag#*=}
eface=${eface_flag#*=}

set +e
echo "--- Current Status"
sudo tc filter show dev "${iface}" ingress
sudo tc filter show dev "${eface}" egress
sudo tc qdisc del dev enp0s3 clsact
sudo bpftool net list

echo "--- Cleaning"
sudo tc filter del dev "${eface}" egress
sudo tc filter del dev "${iface}" ingress

echo "-- Current Status"
sudo tc qdisc show
sudo bpftool net list
