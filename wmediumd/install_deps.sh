#!/usr/bin/env bash

apt-get update
# libs
apt-get install libnl-genl-3-dev libevent-dev libnl-3-dev libconfig-dev
# build environment
apt-get install make gcc
# optional
apt-get install tmux lxc
