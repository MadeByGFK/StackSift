import asyncio
import httpx
import pytest
from fastapi import HTTPException
from starlette.requests import Request
from app import client_ip, main
from app.rate_limit import RateLimiter


def req(headers):
    return Request({'type': 'http', 'client': ('100.64.0.2', 80),
                    'headers': [(k.encode(), v.encode()) for k, v in headers]})


@pytest.fixture(autouse=True)
def railway_mode(monkeypatch):
    monkeypatch.setattr(client_ip, 'PROXY_MODE', 'railway')
    monkeypatch.setattr(client_ip, 'TRUSTED_PROXY_NETWORKS', ())


@pytest.mark.parametrize('value,expected', [
    ('8.8.8.8, 100.64.0.1', '8.8.8.8'),
    ('172.200.1.1', '172.200.1.1'),
    ('2606:4700:0:0:0:0:0:1111, 8.8.8.8', '2606:4700::1111'),
    ('::ffff:8.8.8.8', '8.8.8.8'),
])
def test_railway_first_ip(value, expected):
    assert client_ip.client_ip(req([('x-forwarded-for', value),
        ('x-real-ip', '9.9.9.9')])) == expected


@pytest.mark.parametrize('headers', [
    [], [('x-real-ip', '8.8.8.8')],
    [('x-forwarded-for', 'invalid, 8.8.8.8')],
    [('x-forwarded-for', '172.30.0.1, 8.8.8.8')],
    [('x-forwarded-for', ',8.8.8.8')],
    [('x-forwarded-for', 'fe80::1%eth0')],
    [('x-forwarded-for', '8.8.8.8'), ('x-forwarded-for', '1.1.1.1')],
])
def test_no_shared_proxy_fallback(headers):
    with pytest.raises(HTTPException) as exc:
        client_ip.client_ip(req(headers))
    assert exc.value.status_code == 503


def test_distinct_clients_and_health(monkeypatch):
    monkeypatch.setattr(main, 'limiter', RateLimiter(10, 3600))
    monkeypatch.setattr(main, 'burst_limiter', RateLimiter(2, 60))
    monkeypatch.setattr(main, 'analyze_upload', lambda *args: {})
    monkeypatch.setattr(main, 'render_text_report', lambda data: 'report')
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url='http://test') as c:
            async def post(ip):
                return await c.post('/analyze', headers={'x-forwarded-for': ip},
                    files={'file': ('test.log', b'ERROR synthetic')}, data={'output': 'txt'})
            assert [(await post('8.8.8.8')).status_code for _ in range(3)] == [200, 200, 429]
            assert (await post('1.1.1.1')).status_code == 200
            assert (await c.get('/')).status_code == 503
            assert (await c.get('/health')).status_code == 200
    asyncio.run(run())
