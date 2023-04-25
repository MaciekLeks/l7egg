#!/bin/bash

echo "Traffic Control cleansing tool for clsact qdisc used by l7egg"

iiface_flag=$1
eiface_flag=$2
help='Usage: tc-cleaner -iiface=${iiface} -eiface={$eiface}'

if [[ -z "$iiface_flag" || ! "$iiface_flag" =~ ^-iiface=.+ ]]
then
  echo "Missing or wrong -iiface flag."
  err=1
fi

if [[ -z "$eiface_flag" || ! "$eiface_flag" =~ ^-eiface=.+ ]]
then
  echo "Missing or wrong -eiface flag."
  err=1
fi

if [ -n "$err" ]
then
  echo "$help"
  exit 0
fi

iiface=${iiface_flag#*=}
eiface=${eiface_flag#*=}

set +e
echo "--- Current Status"
sudo tc filter show dev "${iiface}" ingress
sudo tc filter show dev "${eiface}" egress
udo bpftool net list

echo "--- Cleaning"
sudo tc filter del dev "${eiface}" egress
sudo tc filter del dev "${iiface}" ingress
sudo tc qdisc del dev "${iiface}" clsact
sudo tc qdisc del dev "${eiface}" clsact


echo "-- Current Status"
sudo tc qdisc show
sudo bpftool net list
