import sys
import os
import ipaddress
from typing import List, Dict, Set, Any

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detectors.hijack.hijack_utils import logger


def get_target_prefixes(target_as, prefix_to_as):
    try:
        target_prefixes = []

        for prefix, as_set in prefix_to_as.items():
            if target_as in as_set:
                target_prefixes.append(prefix)

        logger.info(f"Found {len(target_prefixes)} prefixes for AS{target_as}")
        return target_prefixes

    except Exception as e:
        logger.error(f"Error getting target prefixes for AS{target_as}: {e}")
        return []


def get_target_prefixes_batch(target_as_list, prefix_to_as):
    try:
        results = {}

        for target_as in target_as_list:
            prefixes = get_target_prefixes(target_as, prefix_to_as)
            results[target_as] = prefixes

        total_prefixes = sum(len(prefixes) for prefixes in results.values())
        logger.info(f"Found {total_prefixes} total prefixes for {len(target_as_list)} ASes")
        return results

    except Exception as e:
        logger.error(f"Error in batch prefix processing: {e}")
        return {}


def validate_prefixes_exist(target_prefixes, prefix_to_as):
    try:
        valid_prefixes = []

        for prefix in target_prefixes:
            if prefix in prefix_to_as:
                valid_prefixes.append(prefix)
            else:
                logger.warning(f"Prefix {prefix} not found in prefix-to-AS mapping")

        if len(valid_prefixes) != len(target_prefixes):
            logger.warning(f"Only {len(valid_prefixes)}/{len(target_prefixes)} target prefixes are valid")

        return valid_prefixes

    except Exception as e:
        logger.error(f"Error validating prefixes: {e}")
        return []


class BinaryPrefixTrie:
    def __init__(self):
        self.root = {}
        self.prefix_count = 0

    def insert(self, prefix):
        try:
            if '/' in prefix:
                network = ipaddress.ip_network(prefix, strict=False)
            else:
                # Assume /32 for IPv4 or /128 for IPv6 if no mask
                network = ipaddress.ip_network(prefix + ('/32' if '.' in prefix else '/128'), strict=False)

            ip_int = int(network.network_address)
            mask_len = network.prefixlen

            if network.version == 4:
                binary = format(ip_int, '032b')[:mask_len]
            else:  # IPv6
                binary = format(ip_int, '0128b')[:mask_len]

            current = self.root
            for bit in binary:
                bit = int(bit)
                if bit not in current:
                    current[bit] = {}
                current = current[bit]

            current['prefix'] = True
            current['mask'] = mask_len
            current['network'] = network
            self.prefix_count += 1

        except Exception as e:
            logger.warning(f"Failed to insert prefix {prefix}: {e}")

    def is_subnet(self, prefix):
        try:
            if '/' in prefix:
                query_network = ipaddress.ip_network(prefix, strict=False)
            else:
                query_network = ipaddress.ip_network(prefix + ('/32' if '.' in prefix else '/128'), strict=False)

            ip_int = int(query_network.network_address)
            query_mask = query_network.prefixlen

            if query_network.version == 4:
                binary = format(ip_int, '032b')
            else:
                binary = format(ip_int, '0128b')

            current = self.root
            matched_prefix = None

            for i, bit in enumerate(binary):
                if i >= query_mask:
                    break

                bit = int(bit)
                if bit not in current:
                    break
                current = current[bit]

                if 'prefix' in current and current['mask'] <= query_mask:
                    stored_network = current['network']
                    if query_network.subnet_of(stored_network):
                        matched_prefix = stored_network
                        break

            return matched_prefix is not None

        except Exception as e:
            logger.warning(f"Failed to check prefix {prefix}: {e}")
            return False

    def get_stats(self):
        return {
            'prefix_count': self.prefix_count,
            'memory_usage': self._estimate_memory_usage()
        }

    def _estimate_memory_usage(self):
        def count_nodes(node):
            count = 1 
            for child in node.values():
                if isinstance(child, dict):
                    count += count_nodes(child)
            return count
        return count_nodes(self.root)


def build_prefix_trie(prefixes):
    trie = BinaryPrefixTrie()
    for prefix in prefixes:
        trie.insert(prefix)
    return trie


def is_subnet_of_trie(prefix, trie):
    return trie.is_subnet(prefix)
