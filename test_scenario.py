#!/usr/bin/env python3
"""
Mininet test scenario for Sentinel DDoS Core

Run this from the Mininet CLI:
  mininet> py exec(open('test_scenario.py').read())

Or as a standalone test:
  sudo python3 test_scenario.py
"""

from mininet.net import Mininet
from mininet.topo import SingleSwitchTopo
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
import time

def run_ddos_test():
    """Simulate a simple DDoS attack for testing Sentinel"""
    
    print("\n=== Sentinel DDoS Test Scenario ===\n")
    
    # Create network with 3 hosts
    topo = SingleSwitchTopo(k=3)
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(
            name, ip='127.0.0.1', port=6633
        ),
        autoSetMacs=True,
        autoStaticArp=True
    )
    
    net.start()
    
    # Get hosts
    h1, h2, h3 = net.get('h1', 'h2', 'h3')
    
    print(f"h1: {h1.IP()}")
    print(f"h2: {h2.IP()}")
    print(f"h3: {h3.IP()}")
    print("")
    
    # Test 1: Normal traffic
    print("[Test 1] Normal ping (should succeed)...")
    result = h1.cmd(f'ping -c 3 {h2.IP()}')
    if 'bytes from' in result:
        print("✓ Normal traffic works")
    else:
        print("✗ Normal traffic failed")
    time.sleep(2)
    
    # Test 2: UDP flood from h1 to h2
    print("\n[Test 2] Simulating UDP flood from h1 to h2...")
    print("  Starting hping3 flood (5 seconds)...")
    
    # Start UDP flood in background
    h1.cmd(f'hping3 -2 -i u1 -p 53 {h2.IP()} &')
    time.sleep(5)
    
    # Kill hping3
    h1.cmd('killall hping3 2>/dev/null')
    
    print("  Flood stopped. Check Sentinel logs for detection.")
    time.sleep(2)
    
    # Test 3: SYN flood from h3 to h2
    print("\n[Test 3] Simulating SYN flood from h3 to h2...")
    print("  Starting SYN flood (5 seconds)...")
    
    h3.cmd(f'hping3 -S -i u1 -p 80 {h2.IP()} &')
    time.sleep(5)
    
    h3.cmd('killall hping3 2>/dev/null')
    
    print("  Flood stopped. Check Sentinel logs for detection.")
    time.sleep(2)
    
    # Test 4: Check if blocked traffic is actually blocked
    print("\n[Test 4] Verifying flows on switch...")
    print("  Query with: curl http://127.0.0.1:8080/stats/flow/1")
    print("")
    
    print("=== Test complete ===")
    print("\nTo run interactive tests, use the Mininet CLI:")
    print("  mininet> h1 ping -c 3 h2")
    print("  mininet> h1 hping3 -S -p 80 -i u1 10.0.0.2")
    print("\nTo check Sentinel flows in Ryu:")
    print("  curl http://127.0.0.1:8080/stats/flow/1 | python3 -m json.tool")
    print("")
    
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_ddos_test()
