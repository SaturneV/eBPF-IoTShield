#!/bin/bash

# Create a network bridge
sudo ip link add br0 type bridge
sudo ip addr add 10.0.0.0/24 dev br0 
sudo ip link set br0 up

# Make the bridge accesible to QEMU
sudo chmod u+s /usr/lib/qemu/qemu-bridge-helper
sudo mkdir -p /etc/qemu
echo 'allow br0' | sudo tee -a /etc/qemu/bridge.conf

# Launch the QEMU VM instances on new terminals
gnome-terminal --title="Host 1" -- bash -c "qemu-system-x86_64 \
	-enable-kvm -cpu host -m 1G \
	-drive file=debian-13-nocloud-amd64-host1.qcow2,format=qcow2 \
	-netdev bridge,id=hn1 \
	-device virtio-net,netdev=hn1,mac=12:34:56:78:00:01 \
	-nographic"

gnome-terminal --title="Host 2" -- bash -c "qemu-system-x86_64 \
        -enable-kvm -cpu host -m 1G \
        -drive file=debian-13-nocloud-amd64-host2.qcow2,format=qcow2 \
        -netdev bridge,id=hn1 \
        -device virtio-net,netdev=hn1,mac=12:34:56:78:00:02 \
        -nographic"

gnome-terminal --title="Host 3" -- bash -c "qemu-system-x86_64 \
        -enable-kvm -cpu host -m 1G \
        -drive file=debian-13-nocloud-amd64-host3.qcow2,format=qcow2 \
        -netdev bridge,id=hn1 \
        -device virtio-net,netdev=hn1,mac=12:34:56:78:00:03 \
        -nographic"
