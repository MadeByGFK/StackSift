import pytest
from starlette.requests import Request
from app import client_ip


def request(peer='100.64.0.1', headers=()):
    return Request({'type': 'http', 'client': (peer, 80),
                    'headers': [(k.encode(), v.encode()) for k, v in headers]})


@pytest.mark.parametrize('raw,expected', [
    ('172.200.1.1', '172.200.1.1'),
    ('2606:4700:0000:0000:0000:0000:0000:1111', '2606:4700::1111'),
    ('::ffff:8.8.8.8', '8.8.8.8'),
    ('172.30.1.1', '100.64.0.1'),
    ('169.254.1.1', '100.64.0.1'),
    ('100.64.0.2', '100.64.0.1'),
    ('127.0.0.1', '100.64.0.1'),
    ('::1', '100.64.0.1'),
    ('fe80::1%eth0', '100.64.0.1'),
    ('224.0.0.1', '100.64.0.1'),
    ('8.8.8.8, 1.1.1.1', '100.64.0.1'),
    ('8.8.8.8:443', '100.64.0.1'),
    ('008.8.8.8', '100.64.0.1'),
    ('invalid', '100.64.0.1'),
])
def test_trusted_ingress(monkeypatch, raw, expected):
    monkeypatch.setattr(client_ip, 'TRUSTED_PROXY_NETWORKS',
                        client_ip.parse_trusted_proxies('100.64.0.1/32'))
    assert client_ip.client_ip(request(headers=[('x-real-ip', raw)])) == expected


def test_headers_ignored_without_trust(monkeypatch):
    monkeypatch.setattr(client_ip, 'TRUSTED_PROXY_NETWORKS', ())
    assert client_ip.client_ip(request('9.9.9.9', [('x-real-ip', '8.8.8.8'),
        ('x-forwarded-for', '1.1.1.1')])) == '9.9.9.9'


def test_trust_does_not_extend_to_other_peers(monkeypatch):
    monkeypatch.setattr(client_ip, 'TRUSTED_PROXY_NETWORKS',
                        client_ip.parse_trusted_proxies('100.64.0.1/32'))
    assert client_ip.client_ip(request('9.9.9.9', [('x-real-ip', '8.8.8.8')])) == '9.9.9.9'
    assert client_ip.client_ip(request(headers=[('x-forwarded-for', '8.8.8.8')])) == '100.64.0.1'
    assert client_ip.client_ip(request(headers=[('x-real-ip', '8.8.8.8'),
        ('x-real-ip', '1.1.1.1')])) == '100.64.0.1'


def test_ipv6_peer_and_mapped_peer(monkeypatch):
    monkeypatch.setattr(client_ip, 'TRUSTED_PROXY_NETWORKS',
                        client_ip.parse_trusted_proxies('fd00::/64,100.64.0.1/32'))
    for peer in ['fd00::1', '::ffff:100.64.0.1']:
        assert client_ip.client_ip(request(peer, [('x-real-ip', '2606:4700::1111')])) == '2606:4700::1111'


@pytest.mark.parametrize('value', ['*', '0.0.0.0/0', '::/0', '10.1.1.1/8'])
def test_invalid_trust_fails_closed(value):
    with pytest.raises(ValueError):
        client_ip.parse_trusted_proxies(value)
