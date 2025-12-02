import controller as ctrl
import subprocess


def run_terminal_command(cmd, msg, show=False):
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
        return True

    except subprocess.CalledProcessError as e:
        print("Return code:", e.returncode)
        print(e.stderr, end="")
        print("Command failed!")
        return False



def execute_exit(args: list[str]):
    print("Exiting the CLI. Goodbye!")


def execute_loadxdp(args: list[str]):
    name = "loadxdp"
    if len(args) != 2:
        print("Usage: " + commands[name]["Usage"])
        return 

    interface = args[1]
    sucess = run_terminal_command("make", "Compiling source code...")
    sucess = sucess and run_terminal_command(f"make load IFACE={interface}", f"Loading the filter on interface {interface}")
    if (sucess):
        print("Filter successfully loaded")

def execute_intls(args: list[str]):
    name = "intls"
    if len(args) != 1:
        print("Usage: " + commands[name]["Usage"])
        return 
    
    run_terminal_command("ls /sys/class/net", "Available interfaces :", show=True)

def execute_unload(args: list[str]):
    name = "unloadxdp"
    if len(args) != 2:
        print("Usage: " + commands[name]["Usage"])
        return 

    interface = args[1]
    sucess = run_terminal_command(f"make unload IFACE={interface}", f"Unloading the filter on interface {interface}")
    if (sucess):
        print("Filter successfully unloaded")
    
def execute_xdpstatus(args: list[str]):
    name = "xdpstatus"
    if len(args) != 1:
        print("Usage: " + commands[name]["Usage"])
        return 
    
    run_terminal_command("sudo xdp-loader status", "XDP filter status on all interfaces :", show=True)


    

commands =  { 
    "exit": {
        "Usage": "exit", 
        "Description": "Exit the command line interface",
        "Handler": execute_exit
    },
    "loadxdp": {
        "Usage": "loadxdp <interface_name>",
        "Description" : "Load the xdp filter on <interface_name>",
        "Handler": execute_loadxdp
    },
    "intls": {
        "Usage": "intls", 
        "Description": "List the available interfaces", 
        "Handler": execute_intls
    },
    "unloadxdp": {
        "Usage": "unloadxdp <interface_name>", 
        "Description": "Unload the filter on interface <interface_name>",
        "Handler": execute_unload
    },
    "xdpstatus": {
        "Usage": "xdpstatus", 
        "Description": "Show the status of the xdp filter on all interfaces",
        "Handler": execute_xdpstatus
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
        print("TODO : Show help")
        return True



if __name__ == "__main__":
    print("Welcome to the command line interface for monitoring the eBPF blacklist/whitelist filter.")
    cont = True
    while(cont):
        command = input("\n> ").strip().lower()
        args = command.split()

        cont = execute_command(args)