"""Threat intelligence feed providers - NVD, OTX, VirusTotal, etc."""

from __future__ import annotations

import httpx
from typing import Optional, List, Dict, Any


class FeedProvider:
    """Base interface for threat intelligence feed providers."""

    async def query(self, query: str) -> List[Dict[str, Any]]:
        """Query the feed for threat intelligence.

        Args:
            query: Search query (CVE ID, IP, domain, etc.)

        Returns:
            List of matching results with metadata
        """
        raise NotImplementedError

    async def close(self) -> None:
        """Clean up resources."""
        pass


class OTXFeed(FeedProvider):
    """AlienVault Open Threat Exchange (OTX) IOC feed."""

    base_url = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: Optional[str] = None):
        """Initialize OTX feed.

        Args:
            api_key: Optional OTX API key (free tier available)
        """
        self.api_key = api_key
        self.client = httpx.AsyncClient(timeout=30.0)
        self.headers = {}
        if api_key:
            self.headers["X-OTX-API-Key"] = api_key

    async def query_ip(self, ip: str) -> Dict[str, Any]:
        """Query IP reputation in OTX.

        Args:
            ip: IPv4 address to query

        Returns:
            Reputation data and threat intelligence
        """
        try:
            response = await self.client.get(
                f"{self.base_url}/indicators/IPv4/{ip}/general",
                headers=self.headers,
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            return {"error": str(e), "ip": ip}

    async def query_domain(self, domain: str) -> Dict[str, Any]:
        """Query domain reputation in OTX.

        Args:
            domain: Domain name to query

        Returns:
            Reputation data and threat intelligence
        """
        try:
            response = await self.client.get(
                f"{self.base_url}/indicators/domain/{domain}/general",
                headers=self.headers,
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            return {"error": str(e), "domain": domain}

    async def query_hash(self, file_hash: str) -> Dict[str, Any]:
        """Query file hash (malware) reputation in OTX.

        Args:
            file_hash: MD5, SHA1, or SHA256 hash

        Returns:
            Reputation data and threat intelligence
        """
        try:
            response = await self.client.get(
                f"{self.base_url}/indicators/file/{file_hash}/general",
                headers=self.headers,
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            return {"error": str(e), "hash": file_hash}

    async def query(self, query: str) -> List[Dict[str, Any]]:
        """Generic query - routes to appropriate method based on input type."""
        results = []

        # Detect query type
        if len(query) == 32 or len(query) == 40 or len(query) == 64:
            # Likely a hash
            result = await self.query_hash(query)
            results.append(result)
        elif "." in query and not "/" in query:
            # Likely a domain
            result = await self.query_domain(query)
            results.append(result)
        elif all(
            0 <= int(x) <= 255 for x in query.split(".") if x.isdigit()
        ):  # Likely an IP
            result = await self.query_ip(query)
            results.append(result)

        return results

    async def close(self) -> None:
        """Close HTTP client."""
        await self.client.aclose()


class VirusTotalFeed(FeedProvider):
    """VirusTotal threat intelligence feed."""

    base_url = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        """Initialize VirusTotal feed.

        Args:
            api_key: VirusTotal API key (required)
        """
        self.api_key = api_key
        self.client = httpx.AsyncClient(timeout=30.0)
        self.headers = {"x-apikey": api_key}

    async def query_ip(self, ip: str) -> Dict[str, Any]:
        """Query IP in VirusTotal."""
        try:
            response = await self.client.get(
                f"{self.base_url}/ip_addresses/{ip}",
                headers=self.headers,
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            return {"error": str(e), "ip": ip}

    async def query_domain(self, domain: str) -> Dict[str, Any]:
        """Query domain in VirusTotal."""
        try:
            response = await self.client.get(
                f"{self.base_url}/domains/{domain}",
                headers=self.headers,
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            return {"error": str(e), "domain": domain}

    async def query(self, query: str) -> List[Dict[str, Any]]:
        """Generic query."""
        results = []

        if "." in query and not "/" in query:
            result = await self.query_domain(query)
            results.append(result)
        else:
            result = await self.query_ip(query)
            results.append(result)

        return results

    async def close(self) -> None:
        """Close HTTP client."""
        await self.client.aclose()


class URLhausFeed(FeedProvider):
    """URLhaus malware URL blocklist feed."""

    base_url = "https://urlhaus-api.abuse.ch/v1"

    def __init__(self):
        """Initialize URLhaus feed (no API key required)."""
        self.client = httpx.AsyncClient(timeout=30.0)

    async def query_url(self, url: str) -> Dict[str, Any]:
        """Query URL in URLhaus."""
        try:
            response = await self.client.post(
                f"{self.base_url}/url/",
                data={"url": url},
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            return {"error": str(e), "url": url}

    async def query(self, query: str) -> List[Dict[str, Any]]:
        """Query URLhaus feed."""
        if query.startswith("http"):
            result = await self.query_url(query)
            return [result]
        return []

    async def close(self) -> None:
        """Close HTTP client."""
        await self.client.aclose()


class AbuseChFeed(FeedProvider):
    """abuse.ch malware hash and botnet feeds."""

    base_url = "https://abuse.ch/api"

    def __init__(self):
        """Initialize abuse.ch feed."""
        self.client = httpx.AsyncClient(timeout=30.0)

    async def query_hash(self, file_hash: str) -> Dict[str, Any]:
        """Query file hash in abuse.ch MBCI."""
        try:
            response = await self.client.post(
                f"{self.base_url}/query",
                json={"query": "get_file", "hash": file_hash},
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            return {"error": str(e), "hash": file_hash}

    async def query(self, query: str) -> List[Dict[str, Any]]:
        """Query abuse.ch feed."""
        if len(query) in (32, 40, 64):  # MD5, SHA1, SHA256
            result = await self.query_hash(query)
            return [result]
        return []

    async def close(self) -> None:
        """Close HTTP client."""
        await self.client.aclose()
