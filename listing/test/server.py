# server.py (Run this on the HOST)
import socket

# The IP of veth-host (The Gateway/Server)
HOST_IP = "192.168.50.1"
PORT = 80

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sock.bind((HOST_IP, PORT))
    print(f"✅ Echo Server listening on {HOST_IP}:{PORT}")
    print("   (Press Ctrl+C to stop)")

    while True:
        # Receive data
        data, addr = sock.recvfrom(1024)
        
        # Send it exactly back to the sender (Bounce it)
        sock.sendto(data, addr)
        
        # Optional: Print to screen so you know it arrived
        # print(f"Received {len(data)} bytes from {addr}")

except OSError as e:
    print(f"❌ Error: Could not bind to {HOST_IP}. Is the interface up?")
    print(f"   Details: {e}")