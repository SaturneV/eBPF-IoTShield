# sudo ip netns exec testns python3 client.py
# sender.py (Run this inside the NAMESPACE)
import socket
import time

# Target: The veth-host IP
TARGET_IP = "192.168.50.1" 
TARGET_PORT = 80

# CONFIGURATION
PACKETS_PER_SECOND = 100
TOTAL_PACKETS = 100000 # Set to 0 for infinite

# Calculate delay (1 / 10 = 0.1 seconds)
DELAY = 1.0 / PACKETS_PER_SECOND
TIMEOUT = 0.1  # If no reply in 200ms, assume dropped

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(TIMEOUT)

print(f"🚀 Starting Test: Sending to {TARGET_IP} at {PACKETS_PER_SECOND} PPS")
print(f"   (XDP Drop Detection Mode)")
print("-" * 40)

stats = {"sent": 0, "received": 0, "dropped": 0}

try:
    while True:
        if TOTAL_PACKETS > 0 and stats["sent"] >= TOTAL_PACKETS:
            break

        stats["sent"] += 1
        msg = f"seq={stats['sent']}".encode()
        
        start_time = time.time()
        
        try:
            # 1. Send Packet
            sock.sendto(msg, (TARGET_IP, TARGET_PORT))
            
            # 2. Wait for Reply (Echo)
            data, server = sock.recvfrom(1024)
            end_time = time.time()
            
            stats["received"] += 1
            print(f"✅ Packet {stats['sent']}: PASSED (RTT: {(end_time - start_time)*1000:.1f}ms)")
            
        except socket.timeout:
            # 3. Timeout = Packet Loss (XDP dropped it)
            stats["dropped"] += 1
            print(f"❌ Packet {stats['sent']}: DROPPED (No Reply)")
            
        except Exception as e:
            print(f"⚠️ Error: {e}")

        # Maintain precise rate
        time_spent = time.time() - start_time
        sleep_time = DELAY - time_spent
        if sleep_time > 0:
            time.sleep(sleep_time)

except KeyboardInterrupt:
    print("\nStopping...")

# Final Report
print("\n" + "="*40)
print(f"TEST RESULTS")
print("="*40)
print(f"Total Sent: {stats['sent']}")
print(f"Passed:     {stats['received']}")
print(f"Dropped:    {stats['dropped']}")
loss_rate = (stats['dropped'] / stats['sent']) * 100 if stats['sent'] > 0 else 0
print(f"Loss Rate:  {loss_rate:.1f}%")
print("="*40)