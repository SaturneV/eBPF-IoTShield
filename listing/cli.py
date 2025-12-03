import controller as ctrl
import subprocess
import re
import json
import ipaddress
import os
import signal

currState = {}
chosen_interface = None

def handle_sigint(signum, frame):
    print("\n[!] Ctrl-C detected")
    # cleanup here
    execute_exit([])
    exit(0)


def parse_maps_to_config(maps):
    config = {
        "ipv4": {"block": [], "allow": []},
        "ipv6": {"block": [], "allow": []}
    }
    
    for map_id, entries in maps.items():
        if not entries or len(entries) == 0:
            continue
            
        first_entry = entries[0]
        data_len = len(first_entry['key']['data'])
        
        if data_len == 4 or (data_len > 4 and all(b == 0 for b in first_entry['key']['data'][4:])):
            for entry in entries:
                try:
                    prefixlen = entry['key']['prefixlen']
                    data = entry['key']['data']
                    action = entry['value']
                    
                    ip_addr = ipaddress.IPv4Address(bytes(data[:4]))
                    
                    if prefixlen == 32:
                        ip_str = str(ip_addr)
                    else:
                        network = ipaddress.IPv4Network(f"{ip_addr}/{prefixlen}", strict=False)
                        ip_str = str(network)
                    if action == 1:
                        config["ipv4"]["block"].append(ip_str)
                    else:
                        config["ipv4"]["allow"].append(ip_str)
                        
                except Exception as e:
                    print(f"Error parsing IPv4 entry: {entry}. Error: {e}")
        
        elif data_len == 16 or data_len > 16:
            for entry in entries:
                try:
                    prefixlen = entry['key']['prefixlen']
                    data = entry['key']['data']
                    action = entry['value']
                    
                    ip_addr = ipaddress.IPv6Address(bytes(data[:16]))
                    
                    if prefixlen == 128:
                        ip_str = str(ip_addr)
                    else:
                        network = ipaddress.IPv6Network(f"{ip_addr}/{prefixlen}", strict=False)
                        ip_str = str(network)
                    
                    if action == 1:
                        config["ipv6"]["block"].append(ip_str)
                    else:
                        config["ipv6"]["allow"].append(ip_str)
                        
                except Exception as e:
                    print(f"Error parsing IPv6 entry: {entry}. Error: {e}")
    return config



def run_terminal_command(cmd, msg, show=False, get_output=False):
    cmd = cmd.strip().split()
    if len(cmd) == 0 :
        print("Trying to execute an empty terminal command")
        return False
    if len(msg) != 0 :
        print(msg)
    try:
        result = subprocess.run(
            cmd,
            check=True,          
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if show :
            print(result.stdout, end="")
        if get_output:
            return True, result.stdout
        return True

    except subprocess.CalledProcessError as e:
        if get_output:
            return False, e.stderr
        print("Return code:", e.returncode)
        print(e.stderr, end="")
        print("Command failed!")
        return False

def choose_interface():
    global chosen_interface
    print("Choose an interface from the list below to work on:")
    success, output = run_terminal_command("ls /sys/class/net", "", get_output=True)
    if not success:
        print("Error retrieving available interfaces.")
        return None

    availableInterfaces = output.strip().split("\n")

    while (True):
        print() #Empty line for better readability
        print("Available interfaces: ")
        print(output)
        interface = input("Enter the interface name: ").strip()
        if interface not in availableInterfaces:
            print(f"Interface {interface} is not available.")
        else:
            chosen_interface = interface
            return


def get_curr_state(first_time=False):
    global currState
    success, output =  run_terminal_command("sudo bpftool net list","Retrieving already loaded interface...", get_output=True)
    if not success: 
        print("Error retrieving loaded interfaces at the startup")
        return False

    valid = False
    lines = output.strip().split("\n")
    for line in lines:
        if "xdp:" in line:
            valid = True
            continue
        if "tc:" in line:
            valid = False
            break
        if valid:
            pattern = re.compile(r"^([a-zA-Z0-9\-]+)\(\d+\).*?id\s+(\d+)")
            match = pattern.search(line)
            if match:
                ifname = match.group(1)
                ifindex = match.group(2)
                if ifname == chosen_interface:
                    currState = {"interface": ifname, "id": ifindex, "previously_initialized": first_time, "loaded": True, "maps": {}, "initialized": False}
                    return True
    currState = {"interface": chosen_interface, "previously_initialized": True, "loaded": False, "id": None, "maps": {}, "initialized": False}
    return True

def get_current_maps():
    if not currState["loaded"]:
        print(f"Interface {chosen_interface} does not have a filter loaded. Please load it first.")
        return None
    if currState["initialized"] == True:
        return currState["maps"]
    success, output = run_terminal_command(f"sudo bpftool prog show id {currState['id']}", "", get_output=True)
    if not success:
        print("Error retrieving eBPF program information.")
        exit(1)
    map_pattern = re.compile(r"map_ids\s+([\d,]+)")

    match = map_pattern.search(output)
    if not match:
        print("No maps found for the eBPF program.")
        exit(1)
    map_ids = match.group(1).split(",")
    maps = {}
    for map_id in map_ids:
        success, output = run_terminal_command(f"sudo bpftool map dump id {map_id}", "", get_output=True)
        if not success:
            print(f"Error retrieving eBPF map information for map id {map_id}.")
            exit(1)
        
        maps[map_id] = json.loads(output.strip().replace('\n', ''))
    return maps

def get_current_maps_from_file():
    if not currState["loaded"]:
        print(f"Interface {chosen_interface} does not have a filter loaded. Please load it first.")
        return None

    with open(currState["config_file"], 'r') as f:
        data = json.load(f)
    print("Current maps successfully retrieved from file.")
    return data

def execute_exit(args: list[str]):
    print("Exiting the CLI. Goodbye!")


def execute_load(args: list[str], reloading=False):
    global chosen_interface
    name = "load"
    if len(args) != 1:
        print("Usage: " + commands[name]["Usage"])
        return 

    interface = chosen_interface
    sucess = run_terminal_command("make", "")
    if currState["loaded"]:
        print(f"Interface {interface} already has a filter loaded.")
        return
    sucess = sucess and run_terminal_command(f"make load IFACE={interface}", "")
    if (sucess):
        get_curr_state()
        if not reloading:
            print("Filter successfully loaded")

def execute_unload(args: list[str], reloading=False):
    global chosen_interface
    name = "unload"
    if len(args) != 1:
        print("Usage: " + commands[name]["Usage"])
        return 

    interface = chosen_interface
    if currState["loaded"] == False:
        print(f"Interface {interface} does not have a filter loaded.")
        return
    sucess = run_terminal_command(f"make unload IFACE={interface}", "")
    if (sucess):
        currState["loaded"] = False
        currState["initialized"] = False
        currState["maps"] = {}
        currState["previously_initialized"] = False
        currState["id"] = None
        if not reloading:
            print("Filter successfully unloaded")

def execute_reload(args: list[str]):
    global chosen_interface
    name = "reload"
    if len(args) != 1:
        print("Usage: " + commands[name]["Usage"])
        return 

    interface = chosen_interface
    if currState["loaded"] == True:
        execute_unload(["unload"], reloading=True)
    execute_load(["load"], reloading=True)
    print("Filter successfully reloaded")
    
def execute_xdpstatus(args: list[str]):
    name = "xdpstatus"
    if len(args) != 1:
        print("Usage: " + commands[name]["Usage"])
        return 
    
    run_terminal_command("sudo xdp-loader status", "XDP filter status on all interfaces :", show=True)

def execute_switch(args: list[str]):
    global chosen_interface
    name = "switch"
    if len(args) != 1:
        print("Usage: " + commands[name]["Usage"])
        return 
    
    choose_interface()
    print(f"Switched to interface: {chosen_interface}")
    if not get_curr_state(first_time=False):
        execute_exit([])



def execute_setrules(args: list[str]):
    name = "setrules"
    if len(args) != 2:
        print("Usage: " + commands[name]["Usage"])
        return
    
    config_file = args[1]
    if not currState["loaded"]:
        print(f"Interface {chosen_interface} does not have a filter loaded. Please load it first.")
        return
    
    if currState["initialized"] == True and config_file == currState["config_file"]:
            print("File already set as configuration file.")
            return 

    if currState["previously_initialized"]: #Filter was loaded previously
        print("Warning: Current eBPF maps may have existing rules. Are you sure you want to replace them?")
        print("If you want to use the currently loaded rules as the configuration file, please use the 'getrules' command instead.")
        confirmation = input("Type 'yes' to confirm, or anything else to cancel: ").strip().lower()
        if confirmation != 'yes':
            print("Operation cancelled.")
            return
    
    print("Clearing existing rules from eBPF maps...")
    execute_reload(["reload"])
    ctrl.load_rules_from_file(config_file)
    currState["initialized"] = True
    currState["previously_initialized"] = True
    with open(config_file, 'r') as f:
        data = json.load(f)
    currState["maps"] = data
    currState["config_file"] = config_file


def execute_getrules(args: list[str]):
    name = "getrules"
    if len(args) != 2:
        print("Usage: " + commands[name]["Usage"])
        return
    
    config_file = args[1]
    if not currState["loaded"]:
        print(f"Interface {chosen_interface} does not have a filter loaded. Please load it first.")
        return
    
    if currState["initialized"] == True:
        print("Error: configuration file already set. You can find the current rules in " + currState["config_file"])
        return
    
    print(f"Storing currently loaded rules into {config_file}...")

    maps = get_current_maps()
    if maps is None:
        print("Failed to retrieve current maps.")
        return
    
    data = parse_maps_to_config(maps)
    
    try:
        with open(config_file, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"Rules successfully saved to {config_file}")
        currState["initialized"] = True
        currState["previously_initialized"] = True
        currState["maps"] = data
        currState["config_file"] = config_file
    except Exception as e:
        print(f"Error saving rules to file: {e}")
    
def execute_status(args: list[str]):
    name = "status"
    if len(args) != 1:
        print("Usage: " + commands[name]["Usage"])
        return 
    
    print(f"Interface: {currState['interface']}")
    print(f"Filter loaded: {'Yes' if currState['loaded'] else 'No'}")
    if currState["loaded"]:
        print(f"Initialized with configuration file: {'Yes' if currState['initialized'] else 'No'}")
        if not currState["initialized"]:
            print("Initialize the filter with a configuration file using the 'setrules' or 'getrules' command.")
            return
        print(f"Configuration file: {currState['config_file']}")
        print("Current Rules:")
        maps = currState["maps"]
        if maps is None:
            print("Failed to retrieve current maps.")
            return
        print("Ipv4:")
        print("  Blocked:")
        for entry in maps.get("ipv4", {}).get("block", []):
            print(f"    - {entry}")
        print("  Allowed:")
        for entry in maps.get("ipv4", {}).get("allow", []):
            print(f"    - {entry}")
        print("Ipv6:")
        print("  Blocked:")
        for entry in maps.get("ipv6", {}).get("block", []):
            print(f"    - {entry}")
        print("  Allowed:")
        for entry in maps.get("ipv6", {}).get("allow", []):
            print(f"    - {entry}")


def execute_add_remove(args: list[str], is_last_operation=True):
    if len(args) != 3:
        print("Usage: ", commands[args[0]]["Usage"])
        return

    if currState["loaded"] == False:
        print("Error: No filter loaded.")
        return
    if currState["initialized"] == False:
        print("Error: Filter not initialized with a configuration file using 'setrules' or 'getrules'.")
        return
    command = args[0]
    action_str = args[1]
    input_str =  args[2]
    if command == "remove":
        ctrl.remove_element_from_map(input_str, action_str, filename=currState["config_file"])
    else:
        ctrl.add_element_to_map(action_str, input_str, filename=currState["config_file"])

    if is_last_operation:
        currState["maps"] = get_current_maps_from_file()

def execute_addall(args: list[str]):
    if len(args) != 2:
        print("Usage: ", commands[args[0]]["Usage"])
        return

    config_file = args[1]
    if currState["loaded"] == False:
        print("Error: No filter loaded.")
        return
    if currState["initialized"] == False:
        print("Error: Filter not initialized with a configuration file using 'setrules' or 'getrules'.")
        return

    print(f"Adding all rules from {config_file}...")

    if not os.path.exists(config_file):
        print(f"Error: {config_file} not found.")
        return

    print(f"Loading rule from {config_file}")
    with open(config_file, 'r') as f:
        data = json.load(f)

    for ip in data.get("ipv4", {}).get("block", []): execute_add_remove(["add", "block", ip], is_last_operation=False)
    for ip in data.get("ipv4", {}).get("allow", []): execute_add_remove(["add", "allow", ip], is_last_operation=False)
    for ip in data.get("ipv6", {}).get("block", []): execute_add_remove(["add", "block", ip], is_last_operation=False)
    for ip in data.get("ipv6", {}).get("allow", []): execute_add_remove(["add", "allow", ip], is_last_operation=False)


    # Finally, update the current state maps
    currState["maps"] = get_current_maps_from_file()
    print("All rules added.")

def execute_help(args: list[str]):
    print("Available commands:")
    for command_name, command_info in commands.items():
        print(f"\t{command_name}: {command_info['Usage']} - {command_info['Description']}")



commands =  { 
    "exit": {
        "Usage": "exit", 
        "Description": "Exit the command line interface",
        "Handler": execute_exit
    },
    "load": {
        "Usage": "load",
        "Description": "Load the xdp filter",
        "Handler": execute_load
    },
    "unload": {
        "Usage": "unload",
        "Description": "Unload the filter",
        "Handler": execute_unload
    },
    "reload": {
        "Usage": "reload",
        "Description": "Reload the filter, clearing all existing rules",
        "Handler": execute_reload
    },
    "xdpstatus": {
        "Usage": "xdpstatus", 
        "Description": "Show the status of the xdp filter on all interfaces",
        "Handler": execute_xdpstatus
    },
    "switch": {
        "Usage": "switch",
        "Description": "Switch to another interface",
        "Handler": execute_switch
    },
    "setrules": {
        "Usage": "setrules <config_file>",
        "Description": "Set the config file and load rules from <config_file> on the loaded filter",
        "Handler": execute_setrules
    }, 
    "getrules": {
        "Usage": "getrules <config_file>",
        "Description": "Set the config file and save the currently used rules on the filter into <config_file>",
        "Handler": execute_getrules
    }, 
    "status": {
        "Usage": "status",
        "Description": "Show the current status",
        "Handler": execute_status
    },
    "add": {
        "Usage": "add <block|allow> <IP>",
        "Description": "Add a rule to block or allow the specified IP address or network",
        "Handler": execute_add_remove
    },
    "remove": {
        "Usage": "remove <block|allow> <IP>",
        "Description": "Remove a rule to block or allow the specified IP address or network",
        "Handler": execute_add_remove
    }, 
    "addall": {
        "Usage": "addall <config_file>",
        "Description": "Add all rules from the specified configuration file to the loaded filter",
        "Handler": execute_addall
    },
    "help": {
        "Usage": "help",
        "Description": "Show this help message",
        "Handler": execute_help
    }

}

def execute_command(args: list[str]):
    if len(args) == 0:
        print("No command entered.")
        return True
    
    command_name = args[0]
    if command_name in commands:
        handler = commands[command_name]["Handler"]
        handler(args)
        return not command_name == "exit"
    else:
        print(f"Unknown command: {command_name}. Type 'help' to see available commands.")
        return True



if __name__ == "__main__":

    signal.signal(signal.SIGINT, handle_sigint)
    print("Welcome to the command line interface for monitoring the eBPF blacklist/whitelist filter.")
    cont = True


    choose_interface() #Sets the global variable chosen_interface
    print(f"Chosen interface: {chosen_interface}")
    if not get_curr_state(first_time=True):
        execute_exit([])

    while(cont):
        command = input(f"\n{chosen_interface}> ").strip().lower()
        args = command.split()

        cont = execute_command(args)