import asyncio
import httpx
from app import main
from app.rate_limit import RateLimiter


def test_http_quota_accounting(monkeypatch):
    monkeypatch.setattr(main, 'limiter', RateLimiter(10, 3600))
    monkeypatch.setattr(main, 'burst_limiter', RateLimiter(2, 60))
    # Isolate admission behavior from the expensive diagnostic pipeline.
    monkeypatch.setattr(main, 'analyze_upload', lambda *args: {})
    monkeypatch.setattr(main, 'render_text_report', lambda data: 'report')
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url='http://test') as c:
            async def post():
                return await c.post('/analyze', files={'file': ('test.log', b'ERROR synthetic')}, data={'output': 'txt'})
            responses = [await post() for _ in range(5)]
            assert [r.status_code for r in responses] == [200, 200, 429, 429, 429]
            assert all(r.headers['retry-after'] == '60' for r in responses[2:])
            assert sum(map(len, main.limiter._hits.values())) == 2
            key = next(iter(main.limiter._hits))
            main.burst_limiter._hits.clear()
            for _ in range(8):
                main.limiter.record(key)
            response = await post()
            assert response.status_code == 429
            assert response.headers['retry-after'] == '3600'
            assert sum(map(len, main.burst_limiter._hits.values())) == 0
    asyncio.run(run())
