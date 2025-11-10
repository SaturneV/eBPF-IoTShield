### Testbench Setup Guide
This guide provides instructions on how to set up a testbench for this project performance evaluation. Please follow 
the step below and keep in mind that the setup may differ based on your specific environment and requirements.

#### Step 0: Get the distribution ISO
Download the distribution you want to use for the testbench. In this guide, we will use Ubuntu 22.04 LTS that can
be downloaded from [here](https://releases.ubuntu.com/22.04/).

#### Step 1: Create the VMs
First, create three VMs disk using `qemu-img`:
```bash
$ qemu-img create -f qcow2 h1.qcow2 10G
$ qemu-img create -f qcow2 h2.qcow2 10G
$ qemu-img create -f qcow2 h3.qcow2 10G
```
The last parameter specifies the disk size, which can be adjusted based on your needs.

Then run the hosts installation using `qemu-system-x86_64` and for each one of them install the distribution:
```bash
$ qemu-system-x86_64 -m 2048 -enable-kvm -cpu host -cdrom ubuntu.iso -boot d -hda h1.qcow2 -net nic -net user
$ qemu-system-x86_64 -m 2048 -enable-kvm -cpu host -cdrom ubuntu.iso -boot d -hda h2.qcow2 -net nic -net user
$ qemu-system-x86_64 -m 2048 -enable-kvm -cpu host -cdrom ubuntu.iso -boot d -hda h3.qcow2 -net nic -net user
```
Mind the `-m` parameter that specifies the memory size allocated to each VM, which can be adjusted based on your
needs and the -`net` parameters that allow network connectivity, which will be needed to install the required packages.

#### Step 2: Install required packages
Once the OS installation is complete, install the required packages on each host:
```bash
$ sudo apt update
$ sudo apt install hping3
$ sudo apt install iperf3
```
*Please be aware that during performance evaluation, the hosts will not have internet access. Therefore, you need
to install all necessary packages beforehand.*

#### Step 3: Configure the network
To enable communication between the VMs, we need to use the hub parameter of QEMU. Shut down all the VMs and then
restart them with the following command:
```bash
$ qemu-system-x86_64 \
  -m 2048 -enable-kvm -cpu host \
  -hda h1.qcow2 \
  -netdev hubport,id=port1,hubid=0 \
  -device e1000,netdev=port1
  
$ qemu-system-x86_64 \
  -m 2048 -enable-kvm -cpu host \
  -hda h2.qcow2 \
  -netdev hubport,id=port2,hubid=0 \
  -device e1000,netdev=port2
  
$ qemu-system-x86_64 \
  -m 2048 -enable-kvm -cpu host \
  -hda h3.qcow2 \
  -netdev hubport,id=port3,hubid=0 \
  -device e1000,netdev=port3
```

#### Step 4: Assign IP addresses
Once the VMs are running, assign IP addresses to each host to enable communications between them.
```bash
# On h1
$ sudo ip addr add 10.0.0.1/24 dev ens3
$ sudo ip link set ens3 up

# On h2
sudo ip addr add 10.0.0.2/24 dev ens3
sudo ip link set ens3 up

# On h3
sudo ip addr add 10.0.0.3/24 dev ens3
sudo ip link set ens3 up
```
The above commands assign static IP addresses to each host. You can choose different IP addresses based on your
network configuration.

*Note that the interface name `ens3` may vary depending on the distribution and version you are using. You can check the
interface name using the `ip addr` command.*

#### Step 5: Verify connectivity
To ensure that the hosts can communicate with each other, use the `ping` command from one host to another, e.g. from
h1 ping h2 and h3:
```bash
$ ping 10.0.0.2
$ ping 10.0.0.3
```
If you receive replies, the network setup is successful and the hosts can communicate with each other. You can now
proceed with the performance evaluation of the project using hping3 and iperf3.