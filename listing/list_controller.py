import sys
import json
import subprocess
import os
import ipaddress

CONFIG_FILE = "list_config.json"
MAP_IPV4_NAME = "map_v4"
MAP_IPV6_NAME = "map_v6"
ACTION_PASS = 0
ACTION_DROP = 1

def is_element_in_config_file(filename, input_str, ip_type_str, action_str):
    """
    Returns true if input_str is already in the config file
    """
    with open(filename, "r") as f:
        config_data = json.load(f)

    try:
        for category in ["allow", "block"]:
            for entry in config_data[ip_type_str][action_str]:
                if (entry == input_str):
                    return True
                
    except Exception as e:
        print(f"Error when traversing the config file looking for {input_str}: {e}")

    return False

def add_element_to_config_file(filename, input_str, ip_type_str, action_str):
    already_exists = is_element_in_config_file(filename, input_str, ip_type_str, action_str)
    if already_exists:
        print(f"'{input_str}' is already in the config file.")
        return
    
    with open(filename, "r") as f:
        config_data = json.load(f)

    try:
        config_data[ip_type_str][action_str].append(input_str)
    except Exception as e:
        print(f"Error when trying to append '{input_str}' to '{action_str}: {e}")
    
    with open(filename, "w") as f:
        json.dump(config_data, f, indent=4)

def remove_element_from_config_file(filename, input_str, ip_type_str, action_str):
    already_exists = is_element_in_config_file(filename, input_str, ip_type_str, action_str)
    if not already_exists:
        print(f"'{input_str}' isn't in the config file.")
        return
    
    with open(filename, "r") as f:
        config_data = json.load(f)

    try:
        config_data[ip_type_str][action_str].remove(input_str)
    except Exception as e:
        print(f"Error when trying to append '{input_str}' to '{action_str}: {e}")
    
    with open(filename, "w") as f:
        json.dump(config_data, f, indent=4)


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
            return "ipv4", prefix_len, ip_bytes
        elif net.version == 6:
            return "ipv6", prefix_len, ip_bytes
            
    except Exception as e:
        print(f"Error parsing IP '{input_str}': {e}")
        return None, None, None

def add_element_to_map(action_str, input_str, init=False):
    ip_type_str, prefix, ip_bytes = get_ip_config(input_str)
    
    if ip_type_str == "ipv4":
        map_name = MAP_IPV4_NAME
    elif ip_type_str == "ipv6":
        map_name = MAP_IPV6_NAME
    else:
        print(f"Invalid ip_type '{ip_type_str}'")
        return

    key = [str(prefix), "0", "0", "0"]
    key.extend(ip_bytes)
    
    action = ACTION_DROP if action_str == "block" else ACTION_PASS
    value = [str(action), "0", "0", "0"]

    cmd = [ "sudo", "bpftool", "map", "update", "name", map_name, "key"] + key + ["value"] + value
    result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode == 0:
        print(f"[{action_str}] {input_str} -> {map_name} (/{prefix})")
        if not init:
            add_element_to_config_file(CONFIG_FILE, input_str, ip_type_str, action_str)

    else:
        print(f"Error: failed to add {input_str} to the eBPF map.")

def remove_element_from_map(input_str, action_str):
    ip_type_str, prefix, ip_bytes = get_ip_config(input_str)

    if ip_type_str == "ipv4":
        map_name = MAP_IPV4_NAME
    elif ip_type_str == "ipv6":
        map_name = MAP_IPV6_NAME
    else:
        print(f"Invalid ip_type '{ip_type_str}'")
        return

    key = [str(prefix), "0", "0", "0"]
    key.extend(ip_bytes)

    cmd = ["sudo", "bpftool", "map", "delete", "name", map_name, "key"] + key    
    result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode == 0:
        print(f"[{action.upper()}] {input_str} -> {map_name} (/{prefix})")
        remove_element_from_config_file(CONFIG_FILE, input_str, ip_type_str, action_str)
    else:
        print(f"Error: failed to remove {input_str} from the eBPF map.")

def load_rules_from_file(filename):
    if not os.path.exists(filename):
        print(f"Error: {filename} not found.")
        return

    print(f"Loading rule from {filename}")
    with open(filename, 'r') as f:
        data = json.load(f)

    for ip in data.get("ipv4", {}).get("block", []): add_element_to_map("block", ip, init=True)
    for ip in data.get("ipv4", {}).get("allow", []): add_element_to_map("allow", ip, init=True)
    for ip in data.get("ipv6", {}).get("block", []): add_element_to_map("block", ip, init=True)
    for ip in data.get("ipv6", {}).get("allow", []): add_element_to_map("allow", ip, init=True)

    print("Rules loaded into eBPF maps.")



if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Initialize:  python3 list_controller.py init")
        print("  Add Rule:    python3 list_controller.py add <block|allow> <IP>")
        print("  Remove Rule: python3 list_controller.py remove <block|allow> <IP>")
        sys.exit(1)

    command = sys.argv[1]

    if command == "init":
        load_rules_from_file(CONFIG_FILE)
    elif command in ["add", "remove"]:
        if len(sys.argv) != 4:
            print(f"Error: Missing arguments for '{command}'.")
            print(f"Usage: python3 list_controller.py {command} <block|allow> <IP>")
            sys.exit(1)

        action = sys.argv[2]
        ip_addr = sys.argv[3]
        if action not in ["block", "allow"]:
            print(f"Error: Invalid category '{action}'. Must be 'block' or 'allow'.")
            sys.exit(1)

        if command == "add":
            add_element_to_map(action, ip_addr)
        elif command == "remove":
            remove_element_from_map(ip_addr, action)
    else:
        print(f"Invalid command '{command}'. Use 'init', 'add', or 'remove'.")