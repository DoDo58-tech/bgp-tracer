import argparse
import json
import sys

def read_json(path):
    with open(path, "r") as f:
        return json.load(f)

def get_relations(obj, relation_key, asn):
    rel_map = obj.get(relation_key, {})
    values = rel_map.get(asn, [])
    try:
        return [str(x) for x in sorted({int(v) for v in values})]
    except ValueError:
        return sorted({str(v) for v in values})

def get_customers(obj, asn):
    providers_map = obj.get("providers", {})
    customers = []
    for customer_asn, provider_list in providers_map.items():
        provider_strs = {str(p) for p in provider_list}
        if asn in provider_strs:
            customers.append(customer_asn)
    try:
        return [str(x) for x in sorted({int(v) for v in customers})]
    except ValueError:
        return sorted({str(v) for v in customers})

def main():
    parser = argparse.ArgumentParser(description="Query providers and peers for an AS.")
    parser.add_argument("asn", help="AS number, e.g., 1299")
    parser.add_argument(
        "-f", "--file",
        default="/data/bgp_tracer/data/asrel/20080801.as-rel.txt.parsed.json",
        help="Path to as-rel parsed JSON file"
    )
    args = parser.parse_args()

    try:
        data = read_json(args.file)
    except Exception as e:
        print(f"Failed to read JSON: {e}", file=sys.stderr)
        sys.exit(1)

    asn = str(args.asn)
    providers = get_relations(data, "providers", asn)
    peers = get_relations(data, "peers", asn)
    customers = get_customers(data, asn)

    print(f"AS{asn} providers ({len(providers)}):")
    print("\n".join(providers) or "(none)")
    print()
    print(f"AS{asn} peers ({len(peers)}):")
    print("\n".join(peers) or "(none)")
    print()
    print(f"AS{asn} customers ({len(customers)}):")
    print("\n".join(customers) or "(none)")

if __name__ == "__main__":
    main()