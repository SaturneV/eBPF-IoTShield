### Testbench Setup Guide
This guide provides instructions on how to set up a virtual testbench for this project performance evaluation. Please 
follow the step below and keep in mind that the setup may differ based on your specific environment and requirements.

#### Step 0: Requirements
Before starting the setup, ensure you have the following packages installed on your host machine:
- qemu-system
- gnome-terminal

#### Step 1: Get the virtual disk images
To allow a easy setup of the testbench, three pre-configured virtual disk images are provided:
- **Host 1 VM**: [debian-13-nocloud-amd64-host1.qcow2]() 
- **Host 2 VM**: [debian-13-nocloud-amd64-host2.qcow2]()
- **Host 3 VM**: [debian-13-nocloud-amd64-host3.qcow2]()

**!Please note that the provided virtual disk images are not yet publicly available!**

Theses images are based on a no-cloud ready to use Debian 13 available [here](https://www.debian.org/distrib/) and 
have been pre-configured with all the necessary dependencies and software required for the testbench. They also include
a yaml file that automatically configures the static IP addresses on boot (available in the ipconfigs/ directory).

Please be aware that the provided virtual disk images are built for amd64 architecture.

#### Step 2: Launch the testbench
To launch the testbench, you can use the provided `testbench_init.sh` script. This script will create a network bridge
and then open three gnome-terminal tabs, each running a QEMU instance for the respective hosts. Be sure to give execute
permissions to the script and to put the virtual disk images in the same directory as the script before running it.

#### Step 3: Access the VMs
Once the testbench is launched, you can access each VM through the respective gnome-terminal tabs. The default login
username is `root` and no password is required.

#### Step 4: Execute the performance evaluation
The subnet of the testbench is `10.0.0.0/24` with the following static IP addresses assigned to each host:
- **Host 1 VM**: `10.0.0.1/24`
- **Host 2 VM**: `10.0.0.2/24`
- **Host 3 VM**: `10.0.0.3/24`

To verify the connectivity between the hosts, you can use the `ping` command from one host to another.

Each VM is pre-configured with the iperf3 and hping3 tools for performance evaluation. You can use these tools to
generate traffic and measure the performance of different mitigator strategies. E.g., you can start an iperf3 server
on host 1 and run iperf3 clients on host 2 and host 3 to generate traffic to attack host 1.

#### Step 5: Clean up
After completing your performance evaluation, you can shutdown the VMs by using the `poweroff` command within each VM
and execute the `testbench_clean.sh` that will delete the bridge network created by the testbench setup script.