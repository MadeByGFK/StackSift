"""Client identity from an explicit trusted ingress policy.

Run Uvicorn with --no-proxy-headers so request.client is the socket peer.
Only configured ingress networks may supply a single X-Real-IP. XFF is
ignored, including on trusted connections; arbitrary chains are not trusted.
"""
import os
from ipaddress import ip_address, ip_network, IPv6Address


def parse_trusted_proxies(value: str) -> tuple:
    """Invalid configuration fails startup instead of silently widening trust."""
    networks = tuple(ip_network(item.strip(), strict=True)
                     for item in value.split(',') if item.strip())
    if any(network.prefixlen == 0 for network in networks):
        raise ValueError('Trust-all proxy networks are not allowed')
    return networks


TRUSTED_PROXY_NETWORKS = parse_trusted_proxies(
    os.getenv('STACKSIFT_TRUSTED_PROXY_CIDRS', '')
)


def _address(value: str):
    # Zones are interface-local, not valid public client identifiers.
    if '%' in value:
        return None
    try:
        address = ip_address(value.strip())
    except ValueError:
        return None
    if isinstance(address, IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address


def client_ip(request) -> str:
    peer = _address(request.client.host) if request.client else None
    if peer is None:
        return 'unknown'
    if any(peer.version == network.version and peer in network
           for network in TRUSTED_PROXY_NETWORKS):
        values = request.headers.getlist('x-real-ip')
        if len(values) == 1:
            forwarded = _address(values[0])
            if (forwarded is not None and forwarded.is_global
                    and not forwarded.is_multicast):
                return str(forwarded)
    # Malformed or absent forwarding data never becomes an arbitrary quota key.
    return str(peer)
