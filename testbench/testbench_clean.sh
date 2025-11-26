#!/bin/bash

#Delete the network bridge
sudo ip link set br0 down
sudo ip link delete br0 type bridge
