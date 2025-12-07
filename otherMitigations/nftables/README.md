# Testing other implementation 

## Nft tables 

### Set up the environment if testing in local 

```bash
# Create a namespace called 'testns'
sudo ip netns add testns

# Create a virtual ethernet pair (veth-host <-> veth-ns)
sudo ip link add veth-host type veth peer name veth-ns

# Plug veth-ns into the namespace
sudo ip link set veth-ns netns testns

# Give IP addresses to both ends
sudo ip addr add 192.168.50.1/24 dev veth-host
sudo ip link set veth-host up

# Namespace side (The "Attacker/User"))
sudo ip netns exec testns ip addr add 192.168.50.2/24 dev veth-ns
sudo ip netns exec testns ip link set veth-ns up
```

### First ruleset

The first rule set is simply dropping every incomming packets on the loopback interface.  
The interface can be changed by changing the line :  
```conf
# Accept loopback (always allow)
iif lo drop
```
To this : where **intname**e is is the name of the wanted interface

```conf
# Accept loopback (always allow)
iif <intname> drop
```

### Second ruleset

The second ruleset limit each ip to a certain rate. 
All interfaces are concerned except "lo" and "enp0s3" used for ssh connection to the vm.  
You can add untouched interfaces by adding this line after existing ones.  
```conf 
iif <intname> accept
```  
You can alos change the limiting rate and the burst value by changing this line:  
```conf
meter ratelimit { ip saddr limit rate over <nb_packet>/<unit_time> burst <nb_packet_in_burst> packets} drop
```

### Third ruleset

The third rule set is the equivalent to the one we created at the XD hook level. It works as follow. 
First the incomming packet is dropped or accpet without rate limiting if its ip is in blacklist or whitelist set respectively.
Then if no entry exist, the ip is subject to the rate limiting explained just above.

Again the rate can be changed as in the second ruleset.  
You can also update the blacklist, whitelist dinamically using those commands:  

```bash 
sudo nft <add|delete> element inet filter <whitelist|blacklist> {<ip.Ad.re.ss>}
```

There are two minors differences with the actual eBPF filter. First it only supports IPV4 but for testing purposes it is considered ok, second in this implementation some of the interface are not concerned. In the current state both enp0s3 and lo are unlimited (mainly for ssh reasons).

Additional notes :  

- If the ip adress is in both blacklist and whitelist sets, the packet will be droped, e.g the blacklist set has priority
- You can list elements of the sets using this command : 
    ```bash
     sudo nft list set inet filter <whitelist|blacklist>
    ```

### Load a rule state

```bash 
# Load and enable the ruleset 
# drop_all.conf, rate_limiting.conf, bwlist.conf are provided in the nftables dir
sudo nft -f <ruleset.conf>
```

### Simple test to verify it works 

After setting the local testing environment you can try the different rule sets after loading them by using ping command.  
```bash 
# Generic command
sudo ip netns exec testns ping -c <number_packets> -i <interval_between_packets> 192.168.50.1
# Example
sudo ip netns exec testns ping -c 5000 -i 0.01 192.168.50.1
```

### Clean up 

To clean up everything set up use the following.
 
```bash
# Delete the namespace (automatically removes veth pair and unloads XDP)
sudo ip netns del testns

# Delete the running ruleset 
sudo nft flush ruleset
```

