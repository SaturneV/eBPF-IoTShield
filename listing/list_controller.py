import sys
import json
import subprocess
import os
import ipaddress

CONFIG_FILE = "list_config.json" #TODO: ALLOW A COMMAND TO 'HOT' RELOAD FROM list_config.json
MAP_IPV4_NAME = "map_v4"
MAP_IPV6_NAME = "map_v6"
ACTION_PASS = 0
ACTION_DROP = 1

def get_ip_config(input_str):
    """
    Parses input and returns:
    - map_name ("map_v4" or "map_v6")
    - prefix_len (int)
    - ip_bytes (list of strings representing bytes)
    """
    try:
        net = ipaddress.ip_network(input_str)
        prefix_len = net.prefixlen
        ip_bytes = [str(b) for b in net.network_address.packed]

        if net.version == 4:
            return MAP_IPV4_NAME, prefix_len, ip_bytes
        elif net.version == 6:
            return MAP_IPV6_NAME, prefix_len, ip_bytes
            
    except ValueError as e:
        print(f"Error parsing IP '{input_str}': {e}")
        return None, None, None

def update_map(action, input_str):
    map_name, prefix, ip_bytes = get_ip_config(input_str)
    
    if map_name != MAP_IPV4_NAME and map_name != MAP_IPV6_NAME:
        return

    key = [str(prefix), "0", "0", "0"]
    key.extend(ip_bytes)
    
    # Value: ACTION_PASS=0, ACTION_DROP=1
    action = ACTION_DROP if action == "block" else ACTION_PASS
    value = [str(action), "0", "0", "0"]

    cmd = [ "sudo", "bpftool", "map", "update", "name", map_name, "key"] + key + ["value"] + value
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[{action.upper()}] {input_str} -> {map_name} (/{prefix})")

def load_rules_from_file(filename):
    if not os.path.exists(filename):
        print(f"Error: {filename} not found.")
        return

    print(f"--- Loading rule from {filename} ---")
    with open(filename, 'r') as f:
        data = json.load(f)

    for ip in data.get("ipv4", {}).get("block", []): update_map("block", ip)
    for ip in data.get("ipv4", {}).get("allow", []): update_map("allow", ip)
    for ip in data.get("ipv6", {}).get("block", []): update_map("block", ip)
    for ip in data.get("ipv6", {}).get("allow", []): update_map("allow", ip)

    print("--- Init Complete ---")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 list_controller.py [init | block <IP> | allow <IP>]")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == "init":
        load_rules_from_file(CONFIG_FILE)
    elif mode in ["block", "allow"] and len(sys.argv) == 3:
        update_map(mode, sys.argv[2])
    else:
        print("Invalid arguments.")