# eBPF-IoTShield IP Filtering System

An XDP-based network filtering system for blocking and allowing IPv4 and IPv6 traffic at the kernel level. This tool provides a command-line interface to manage IP blocklists and allowlists with high-performance eBPF/XDP filtering.

## Features

- **IPv4 and IPv6 support** with CIDR notation for network ranges
- **XDP-based filtering** for ultra-fast packet processing
- **Interactive CLI** for real-time rule management
- **Persistent configuration** via JSON files
- **Dynamic rule updates** without reloading the filter

## Prerequisites

- Linux kernel with XDP support (kernel 4.8+)
- `bpftool` installed
- Root/sudo privileges
- Python 3.x
- Compiled eBPF object file (`listing.o`)

## Project Structure

```
listing/
├── listing.c           # eBPF/XDP filter source code
├── cli.py              # Interactive command-line interface
├── controller.py       # Core logic for managing eBPF maps
├── config.json         # Default configuration file
├── Makefile            # Build system
└── README.md           # This file
```

## Building

Compile the eBPF filter:

```bash
make
```

This generates `listing.o`, the eBPF object file that will be loaded onto network interfaces.

## Testing Environment Setup

For local testing without affecting your main network interface, use a virtual network namespace with a veth pair. This creates an isolated environment where you can safely test the filter.

### 1. Create Virtual Network Environment

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

### 2. Verify Connectivity

Before loading the filter, ensure the virtual network works:

```bash
# Ping from namespace to host
sudo ip netns exec testns ping -c 2 192.168.50.1
```

You should see successful ping responses.

## Usage

### Starting the CLI

**- Important -**

The command-line interface assumes that only the CLI modifies the filter state while it is running.
This is required because the CLI relies on a configuration file that must be initialized before adding or removing rules. This file acts as a dynamic mirror of the maps loaded in the eBPF filter: whenever a rule is added or removed through the CLI, both the filter maps and the configuration file (config_file.json) are updated accordingly.

If the eBPF filter’s maps or the configuration file are modified by another process while the CLI is running, they may become desynchronized, which can lead to undefined or inconsistent behavior.

Launch the interactive CLI:

```bash
sudo python3 cli.py
```

The CLI will prompt you to select a network interface.

### Example Workflow

Here's a complete workflow demonstrating the filter's capabilities:

#### 1. Initial Setup

```
# Start the CLI and select your interface (e.g., veth-host for testing)
sudo python3 cli.py

# Check current status
veth-host> status

# Check XDP status on all interfaces
veth-host> xdpstatus
```

#### 2. Load the Filter

```
# Load the XDP filter onto the current interface
veth-host> load

# Verify it loaded successfully
veth-host> status
```

#### 3. Initialize Configuration

**This step is mandatory**  
As explained earlier, the CLI operates using a local copy of the eBPF filter’s maps stored in a configuration file. Before adding, removing, or updating rules, a configuration file must be selected.
To support this, the CLI provides two commands that initialize the configuration file in different ways.

The objective is to allow the CLI to exit while keeping the filter running, and later restart the CLI and recover the current state from the running filter.  

##### **`setrules`**  
This command takes a configuration file as argument (following the format of `config.json`) and sets the filter’s rules to **exactly match** the rules defined in that file.  
It is useful for quickly initializing a filter without adding each rule manually.

**Be careful when using this command.**  
If a filter is already running, `setrules` will **reload the filter erasing all existing rules** and replacing them with the rules provided in the configuration file.

##### **`getrules`**  
This command takes a configuration file as argument and retrieves the rules currently used by the running filter, then writes them to the file.  
It is useful for incrementally modifying the current filter without having to reload the entire rule set.

```
# Set configuration file and write the rules in the filter(the file must exist)
veth-host> setrules config.json

#or 
# Set the configuration file and load the rules from the filter(create the file if it does not exits)
veth-host> getrules config.json
```

#### 4. Add Filtering Rules

```
# Block a specific IP address
veth-host> add block 192.168.50.2

# Block an entire subnet
veth-host> add block 10.0.0.0/24

# Allow a specific IP (whitelist mode when combined with broader blocks)
veth-host> add allow 192.168.1.100

# Block IPv6 address
veth-host> add block 2001:db8::1

# Block IPv6 subnet
veth-host> add block 2001:db8::/32
```

#### 5. View Current Rules

```
# Display all active rules
veth-host> status
```

#### 6. Remove Rules

```
# Remove a block rule
veth-host> remove allow 192.168.1.100

# Remove an allow rule
veth-host> remove block 2001:db8::/32
```

#### 7. Batch Operations

```
# Add all rules from a configuration file
veth-host> addall custom_rules.json
```

#### 8. Switch Interfaces

```
# Change to a different network interface
veth-host> switch
# Follow the prompts to select a new interface
```

#### 9. Reload or Unload

```
# Reload the filter (clears all rules and reloads fresh)
veth-host> reload

# Unload the filter completely
veth-host> unload
```

#### 10. Exit

```
# Exit the CLI
veth-host> exit
```

## Testing the Filter

Once the filter is loaded and rules are configured, test it with the virtual network environment:

### Test Blocking

```bash
# Add a block rule for the namespace IP using the cli
veth-host> add block 192.168.50.2

# Try to ping from the namespace (should fail)
sudo ip netns exec testns ping -c 4 192.168.50.1
# Expected: 100% packet loss
```

### Verify with tcpdump

To confirm XDP is dropping packets **before** they reach the network stack:

```bash
# In one terminal, start tcpdump on the host side
sudo tcpdump -i veth-host -n icmp

# In another terminal, ping from the namespace
sudo ip netns exec testns ping -c 4 192.168.50.1
```

**Expected behavior:**
- **If XDP is working:** tcpdump shows **no packets** (XDP drops before tcpdump sees them)
- **If using iptables:** tcpdump would show packets (dropped after network stack)

### Test Allowing

```bash
# Remove the block rule in the cli
veth-host> remove block 192.168.50.2

# Try to ping again (should succeed)
sudo ip netns exec testns ping -c 4 192.168.50.1
# Expected: Successful pings
```

## Cleanup

### Remove Virtual Test Environment

When you're done testing:

```bash
# Delete the namespace (automatically removes veth pair and unloads XDP)
sudo ip netns del testns
```

## Configuration File Format

The JSON configuration file has the following structure:

```json
{
  "ipv4": {
    "block": [
      "192.168.1.100",
      "10.0.0.0/24"
    ],
    "allow": [
      "192.168.1.50"
    ]
  },
  "ipv6": {
    "block": [
      "2001:db8::1",
      "2001:db8::/32"
    ],
    "allow": [
      "2001:db8::100"
    ]
  }
}
```

## CLI Commands Reference

| Command | Usage | Description |
|---------|-------|-------------|
| `help` | `help` | Show all available commands |
| `status` | `status` | Display current filter status and loaded rules |
| `xdpstatus` | `xdpstatus` | Show XDP status on all interfaces |
| `load` | `load` | Load XDP filter onto current interface |
| `unload` | `unload` | Unload XDP filter from current interface |
| `reload` | `reload` | Reload filter (clears all rules) |
| `switch` | `switch` | Switch to a different network interface |
| `setrules` | `setrules <file>` | Load rules from configuration file |
| `getrules` | `getrules <file>` | Save current rules to configuration file |
| `add` | `add <block\|allow> <IP>` | Add a block or allow rule |
| `remove` | `remove <block\|allow> <IP>` | Remove a block or allow rule |
| `addall` | `addall <file>` | Add all rules from configuration file |
| `exit` | `exit` | Exit CLI and cleanup |

## IP Address Formats

Both IPv4 and IPv6 addresses are supported with CIDR notation:

- **Single IPv4:** `192.168.1.100`
- **IPv4 Network:** `10.0.0.0/24`
- **Single IPv6:** `2001:db8::1`
- **IPv6 Network:** `2001:db8::/32`

## Notes

- XDP programs run in **generic mode** on virtual interfaces (veth, bridge) and **native mode** on physical NICs with driver support.
- Rules persist in the configuration file and can be reloaded after reboot.
- The filter uses a **default-allow** policy: only explicitly blocked IPs are dropped.
- All CLI operations that modify eBPF maps require sudo privileges.
