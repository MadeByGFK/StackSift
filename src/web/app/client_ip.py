"""Client identity using the deployment's explicit proxy policy.

Railway public HTTP mode trusts the platform-controlled leftmost XFF value.
It requires Railway HTTP ingress as the public boundary (no direct TCP
exposure); private-network callers must also be trusted. Other deployments
retain the CIDR-based X-Real-IP policy. Uvicorn must not rewrite socket peers.
"""
import os
from ipaddress import ip_address, ip_network, IPv6Address
from fastapi import HTTPException

PROXY_MODE = os.getenv("STACKSIFT_PROXY_MODE", "cidr").strip()
if PROXY_MODE not in {"cidr", "railway"}:
    raise ValueError("STACKSIFT_PROXY_MODE must be cidr or railway")


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
    if PROXY_MODE == 'railway':
        values = request.headers.getlist('x-forwarded-for')
        # Railway staff recommend exactly the first entry. Never scan past an
        # invalid/private first entry to select an infrastructure hop instead.
        if len(values) == 1:
            first = _address(values[0].split(',', 1)[0])
            if first is not None and first.is_global and not first.is_multicast:
                return str(first)
        # Do not silently group clients by proxy IP or switch to X-Real-IP,
        # which can describe a CDN hop. /health does not call this function.
        raise HTTPException(
            status_code=503,
            detail='Client address unavailable. Please try again later.',
            headers={'Retry-After': '60'},
        )
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
