# Standalone DCP Network Simulator (RFC-0011 & RFC-0013)
# Simulates reputation scoring updates and dynamic route adaptation under packet drops/latency injection.

import random
import time

class VirtualRelay:
    def __init__(self, name, base_latency=15):
        self.name = name
        self.base_latency = base_latency
        self.latency = base_latency
        self.total_requests = 0
        self.failed_requests = 0
        self.mailbox_count = 0
        self.active_connections = 0
        self.uptime = 1.0
        self.health = 1.0
        self.online = True

    def simulate_request(self):
        if not self.online:
            self.total_requests += 1
            self.failed_requests += 1
            return None # Drop
            
        self.total_requests += 1
        # Random drop based on health
        if random.random() > self.health:
            self.failed_requests += 1
            return None
            
        # Add slight jitter to latency
        jitter = random.randint(-5, 5)
        return max(1, self.latency + jitter)

    def inject_fault(self, fault_type):
        if fault_type == "latency_spike":
            self.latency = random.randint(150, 450)
            print(f"   [Fault Injector] Injected latency spike on {self.name} ({self.latency}ms)")
        elif fault_type == "packet_drops":
            self.health = 0.60
            print(f"   [Fault Injector] Injected 40% packet drops on {self.name}")
        elif fault_type == "disconnect":
            self.online = False
            self.uptime = 0.0
            print(f"   [Fault Injector] Disconnected {self.name} (Offline)")

    def heal(self):
        self.latency = self.base_latency
        self.health = 1.0
        self.online = True
        self.uptime = 1.0
        print(f"   [Fault Injector] Restored health on {self.name} (Online, latency: {self.latency}ms)")

class DCPClientObserver:
    def __init__(self, name, profile="balanced"):
        self.name = name
        self.profile = profile
        self.history = {} # { relay_name: [obs_latencies] }
        self.recently_used = []

    def observe(self, relay_name, latency):
        if relay_name not in self.history:
            self.history[relay_name] = []
        if latency is None:
            self.history[relay_name].append(999) # Timeout representation
        else:
            self.history[relay_name].append(latency)
        if len(self.history[relay_name]) > 10:
            self.history[relay_name].pop(0)

    def calculate_score(self, relay: VirtualRelay):
        # Retrieve observations
        obs = self.history.get(relay.name, [])
        if not obs:
            avg_latency = relay.latency
            delivery_rate = 1.0
        else:
            valid_obs = [x for x in obs if x != 999]
            avg_latency = sum(valid_obs) / len(valid_obs) if valid_obs else 999
            delivery_rate = len(valid_obs) / len(obs)
            
        latency_factor = max(0, 100 - (avg_latency / 10))
        uptime = relay.uptime
        health = relay.health
        mailbox = 1.0 # default simulated mailbox success
        
        # Profile Weights
        if self.profile == "balanced":
            w = { "latency": 0.20, "uptime": 0.30, "delivery": 0.20, "mailbox": 0.10, "health": 0.20 }
        elif self.profile == "latency":
            w = { "latency": 0.50, "uptime": 0.15, "delivery": 0.10, "mailbox": 0.10, "health": 0.15 }
        elif self.profile == "reliability":
            w = { "latency": 0.10, "uptime": 0.40, "delivery": 0.20, "mailbox": 0.15, "health": 0.15 }
        else: # privacy
            w = { "latency": 0.10, "uptime": 0.20, "delivery": 0.10, "mailbox": 0.10, "health": 0.50 }

        score = (
            (latency_factor * w["latency"]) +
            (uptime * 100 * w["uptime"]) +
            (delivery_rate * 100 * w["delivery"]) +
            (mailbox * 100 * w["mailbox"]) +
            (health * 100 * w["health"])
        )
        
        # Route Diversity Penalty: -15 if recently used
        if relay.name in self.recently_used:
            score = max(0, score - 15)

        return round(score)

    def select_onion_path(self, relays):
        # Calculate scores
        scored = []
        for r in relays:
            score = self.calculate_score(r)
            scored.append((r, score))
            
        # Sort by score descending
        scored.sort(key=lambda x: x[1], reverse=True)
        
        # Choose top 3 relays for onion path
        path = scored[:3]
        
        # Record recently used to trigger route diversity penalty in next round
        self.recently_used = [x[0].name for x in path]
        return path

def run_simulation():
    print("==================================================")
    print("       DCP STANDALONE NETWORK SIMULATOR           ")
    print("==================================================")
    
    # 1. Initialize 10 Virtual Relays
    relays = [
        VirtualRelay("Relay-A", 12),
        VirtualRelay("Relay-B", 18),
        VirtualRelay("Relay-C", 15),
        VirtualRelay("Relay-D", 22),
        VirtualRelay("Relay-E", 14),
        VirtualRelay("Relay-F", 30),
        VirtualRelay("Relay-G", 25),
        VirtualRelay("Relay-H", 40),
        VirtualRelay("Relay-I", 50),
        VirtualRelay("Relay-J", 16)
    ]
    
    # 2. Client Observers
    client_balanced = DCPClientObserver("Alice-Balanced", "balanced")
    client_latency = DCPClientObserver("Alice-LatencyOpt", "latency")
    
    print(f"Configured {len(relays)} Virtual Relay Nodes.")
    print("Simulating 5 initial rounds of normal traffic...")
    
    # Run initial normal traffic
    for r in range(5):
        for relay in relays:
            lat = relay.simulate_request()
            client_balanced.observe(relay.name, lat)
            client_latency.observe(relay.name, lat)
            
    # Print initial scores
    print("\nInitial Client Reputation Scores:")
    for r in relays:
        sc_bal = client_balanced.calculate_score(r)
        sc_lat = client_latency.calculate_score(r)
        print(f" -> {r.name}: Balanced Score = {sc_bal} | Latency Score = {sc_lat}")

    # Select initial onion path
    path = client_balanced.select_onion_path(relays)
    path_names = " -> ".join([p[0].name for p in path])
    print(f"\n[Alice-Balanced] Selected initial onion path: {path_names} (scores: {[p[1] for p in path]})")
    
    # 3. Inject fault: Latency spike on Relay-A and packet drop on Relay-E
    print("\n--- INJECTING NETWORK FAULTS ---")
    relays[0].inject_fault("latency_spike") # Relay-A
    relays[4].inject_fault("disconnect")    # Relay-E (Offline)
    
    # Run 5 rounds under faulty conditions
    print("\nSimulating 5 rounds of message routing under faulty conditions...")
    for r in range(5):
        for relay in relays:
            lat = relay.simulate_request()
            client_balanced.observe(relay.name, lat)
            client_latency.observe(relay.name, lat)
            
    # Calculate scores again
    print("\nUpdated Reputation Scores After Faults:")
    for r in relays:
        sc_bal = client_balanced.calculate_score(r)
        sc_lat = client_latency.calculate_score(r)
        print(f" -> {r.name}: Balanced Score = {sc_bal} | Latency Score = {sc_lat}")
        
    # Alice-Balanced path selection after faults
    new_path = client_balanced.select_onion_path(relays)
    new_path_names = " -> ".join([p[0].name for p in new_path])
    print(f"\n[Alice-Balanced] Selected new onion path: {new_path_names} (scores: {[p[1] for p in new_path]})")
    
    # Assertions to prove client adapted
    # Relay-A should have dropped in rank or score
    assert client_balanced.calculate_score(relays[0]) < 98, "Relay-A score did not drop under latency spike!"
    assert client_balanced.calculate_score(relays[4]) < 70, "Relay-E (offline) score did not drop under disconnect!"
    
    # Confirm Relay-A and Relay-E are NOT in the new path
    new_path_keys = [p[0].name for p in new_path]
    assert "Relay-A" not in new_path_keys, "Relay-A was not avoided despite latency spike!"
    assert "Relay-E" not in new_path_keys, "Offline Relay-E was not avoided!"
    
    print("\n[Simulator Success] Path adaptation verified! Offline/Lagging nodes successfully bypassed.")
    print("==================================================")

if __name__ == "__main__":
    run_simulation()
