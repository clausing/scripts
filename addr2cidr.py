#!/usr/bin/env python3
"""
    Name: addr2cidr.py
    Author: Jim Clausing
    Date: 2025-09-04

    Description:
        Take 2 IP addresses (v4 or v6) and return the smallest cidr block that contains both

"""

import sys
import ipaddress

def smallest_supernet(addr1, addr2):
    # Parse addresses (IPv4 or IPv6)
    ip1 = ipaddress.ip_address(addr1)
    ip2 = ipaddress.ip_address(addr2)

    # Ensure both are same IP version
    if ip1.version != ip2.version:
        raise ValueError("IP versions do not match (one is IPv4, the other is IPv6)")

    # Convert to integers
    i1, i2 = int(ip1), int(ip2)
    diff = i1 ^ i2

    # Total bits: 32 for IPv4, 128 for IPv6
    total_bits = ip1.max_prefixlen

    # Determine common‐prefix length
    if diff == 0:
        prefix_len = total_bits
    else:
        prefix_len = total_bits - diff.bit_length()

    # Build the mask and derive network integer
    mask_int = ((1 << total_bits) - 1) ^ ((1 << (total_bits - prefix_len)) - 1)
    net_int = i1 & mask_int

    # Construct the correct network object
    network = ipaddress.ip_network((net_int, prefix_len), strict=False)
    return network

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <IP-addr-1> <IP-addr-2>")
        sys.exit(1)

    a, b = sys.argv[1], sys.argv[2]
    try:
        supernet = smallest_supernet(a, b)
        print(supernet)
    except ValueError as ve:
        print(f"Error: {ve}")
        sys.exit(1)
    except ipaddress.AddressValueError as ae:
        print(f"Invalid IP address: {ae}")
        sys.exit(1)

if __name__ == "__main__":
    main()

