"""HTTP transport for the opt-in Phoenixd BOLT11 prototype."""
from urllib.parse import urlsplit

import httpx


class PhoenixdClient:
    def __init__(self, base_url: str, password: str):
        url = urlsplit(base_url)
        if (
            url.scheme not in {"http", "https"} or not url.hostname
            or url.username is not None or url.password is not None
            or url.query or url.fragment
        ):
            raise ValueError("Invalid Phoenixd server URL")
        if not password.strip():
            raise ValueError("A Phoenixd HTTP password is required")
        self._base_url = base_url.rstrip("/")
        self._auth = httpx.BasicAuth("", password)

    async def _request(self, method: str, path: str, **kwargs):
        async with httpx.AsyncClient(
            base_url=self._base_url, auth=self._auth, follow_redirects=False,
            timeout=httpx.Timeout(90, connect=5),
        ) as client:
            response = await client.request(method, path, **kwargs)
            response.raise_for_status()
            return response.json()

    async def create_invoice(self, amount_sat: int, description: str) -> dict:
        return await self._request("POST", "createinvoice", data={
            "amountSat": amount_sat,
            "description": description,
        })

    async def pay_invoice(self, invoice: str, amount_sat: int | None = None) -> dict:
        data = {"invoice": invoice}
        if amount_sat is not None:
            data["amountSat"] = str(amount_sat)
        return await self._request("POST", "payinvoice", data=data)

    async def list_incoming(self, *, limit: int = 20, offset: int = 0) -> list[dict]:
        return await self._request("GET", "payments/incoming", params={
            "limit": limit, "offset": offset,
        })

    async def list_outgoing(self, *, limit: int = 20, offset: int = 0) -> list[dict]:
        return await self._request("GET", "payments/outgoing", params={
            "limit": limit, "offset": offset,
        })
