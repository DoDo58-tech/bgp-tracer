import os
import sys
from datetime import datetime
import polars as pl
from config import DEFAULT_ANOMALY_THRESHOLD

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

class SimpleLogger:
    def info(self, msg):
        print(f"[HIJACK INFO] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {msg}")

    def warning(self, msg):
        print(f"[HIJACK WARN] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {msg}")

    def error(self, msg):
        print(f"[HIJACK ERROR] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {msg}")

logger = SimpleLogger()


def build_as_pair_set(as_relationships):
    as_pairs = set()

    providers_map = as_relationships.get('providers', {})
    peers_map = as_relationships.get('peers', {})

    for customer, providers in providers_map.items():
        for provider in providers:
            as_pairs.add((provider, customer))  # provider -> customer
            as_pairs.add((customer, provider))  # customer -> provider (for path traversal)

    # Add peer relationships (bidirectional)
    for as1, peers in peers_map.items():
        for as2 in peers:
            as_pairs.add((as1, as2))
            as_pairs.add((as2, as1))

    return as_pairs
