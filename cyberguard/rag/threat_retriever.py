"""RAG retriever for threat intelligence - NVD, OTX, and other feeds."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from datetime import datetime, timedelta
from typing import Any, List, Optional
from urllib.parse import quote

import httpx
from langchain_core.documents import Document
from langchain_core.retrievers import BaseRetriever
from pydantic import ConfigDict, Field


class NVDCache:
    """Simple in-memory cache for NVD queries with TTL."""

    def __init__(self, ttl_seconds: int = 3600):
        self.cache: dict[str, tuple[Any, float]] = {}
        self.ttl_seconds = ttl_seconds

    def get(self, key: str) -> Optional[Any]:
        """Get cached value if not expired."""
        if key not in self.cache:
            return None
        value, timestamp = self.cache[key]
        if time.time() - timestamp > self.ttl_seconds:
            del self.cache[key]
            return None
        return value

    def set(self, key: str, value: Any) -> None:
        """Store value with timestamp."""
        self.cache[key] = (value, time.time())

    def clear(self) -> None:
        """Clear all cached entries."""
        self.cache.clear()


class NVDRetriever(BaseRetriever):
    """Retrieves CVE data from the National Vulnerability Database (NVD)."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str = "nvd_retriever"
    base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    api_key: Optional[str] = None
    cache: NVDCache = Field(default_factory=lambda: NVDCache())
    client: httpx.AsyncClient = Field(default_factory=lambda: httpx.AsyncClient(timeout=30.0))
    rate_limit_delay: float = 0.6
    last_request_time: float = 0.0

    def __init__(self, api_key: Optional[str] = None, cache_ttl: int = 3600):
        """
        Initialize NVD retriever.

        Args:
            api_key: Optional NVD API key (increases rate limit if provided)
            cache_ttl: Cache time-to-live in seconds (default 1 hour)
        """
        super().__init__(
            api_key=api_key,
            cache=NVDCache(ttl_seconds=cache_ttl),
            client=httpx.AsyncClient(timeout=30.0),
            last_request_time=0.0,
        )

    async def _rate_limit_wait(self) -> None:
        """Enforce rate limiting for NVD API."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - elapsed)
        self.last_request_time = time.time()

    def _extract_package_and_version(self, query: str) -> tuple[str, Optional[str]]:
        """Extract package name and version from query string.

        Examples:
            "postgresql 13.5" → ("postgresql", "13.5")
            "CVE-2021-32027" → ("CVE-2021-32027", None)
            "log4j vulnerability" → ("log4j", None)
        """
        # Check if it's a CVE ID
        cve_match = re.search(r"CVE-\d{4}-\d{4,7}", query, re.I)
        if cve_match:
            return cve_match.group(0).upper(), None

        # Extract package name and version
        parts = query.lower().split()
        package = parts[0] if parts else query

        version = None
        for i, part in enumerate(parts[1:], 1):
            # Look for version-like strings (digits with dots)
            if re.match(r"^\d+(\.\d+)*", part):
                version = part
                break

        return package, version

    async def _query_nvd_api(
        self, keyword: Optional[str] = None, cve_id: Optional[str] = None
    ) -> dict[str, Any]:
        """Query NVD API with keyword or CVE ID.

        Args:
            keyword: Search keyword (e.g., "postgresql 13.5")
            cve_id: Specific CVE ID (e.g., "CVE-2021-32027")

        Returns:
            API response as dictionary
        """
        # Check cache first
        cache_key = hashlib.md5(f"{keyword or cve_id}".encode()).hexdigest()
        cached = self.cache.get(cache_key)
        if cached:
            return cached

        # Enforce rate limiting
        await self._rate_limit_wait()

        # Build query parameters
        params: dict[str, str] = {}
        if cve_id:
            params["cveId"] = cve_id
        elif keyword:
            params["keywordSearch"] = keyword

        # Add API key if provided (increases rate limit from 5 to 50 req/30 min)
        if self.api_key:
            params["apiKey"] = self.api_key

        try:
            response = await self.client.get(self.base_url, params=params)
            response.raise_for_status()
            data = response.json()
            self.cache.set(cache_key, data)
            return data
        except httpx.HTTPError as e:
            return {"vulnerabilities": [], "error": str(e)}

    def _format_cve_document(self, cve_item: dict[str, Any], rank: int = 0) -> Document:
        """Format a single CVE into a LangChain Document.

        Args:
            cve_item: CVE data from NVD API
            rank: Relevance rank (lower is better)

        Returns:
            LangChain Document with metadata
        """
        cve = cve_item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")
        metrics = cve.get("metrics", {})

        # Extract CVSS scores (prefer v3 over v2)
        cvss_v3 = metrics.get("cvssV3", {})
        cvss_v2 = metrics.get("cvssV2", {})
        cvss_score = cvss_v3.get("baseScore") or cvss_v2.get("baseScore") or 0
        cvss_severity = cvss_v3.get("baseSeverity") or cvss_v2.get("baseSeverity") or "UNKNOWN"

        # Extract descriptions
        descriptions = cve.get("descriptions", [])
        primary_desc = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"), ""
        )

        # Extract affected packages
        configs = cve.get("configurations", [])
        affected_packages = []
        for config in configs[:3]:  # Limit to first 3
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria", "")
                    if "cpe:2.3" in cpe:
                        # Extract package name from CPE
                        parts = cpe.split(":")
                        if len(parts) >= 5:
                            affected_packages.append(f"{parts[3]}:{parts[4]}")

        # Extract references
        references = [ref.get("url", "") for ref in cve.get("references", [])][:5]

        # Build content
        content = f"""CVE: {cve_id}
Severity: {cvss_severity}
CVSS Score: {cvss_score}

Description:
{primary_desc}

Affected Packages:
{chr(10).join(f"  • {pkg}" for pkg in affected_packages) if affected_packages else "  • Information not available"}

References:
{chr(10).join(f"  • {ref}" for ref in references) if references else "  • Information not available"}
"""

        # Build metadata
        metadata = {
            "source": "nvd",
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "severity": cvss_severity.lower(),
            "published_date": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
            "affected_packages": affected_packages,
            "rank": rank,
            "references": references,
        }

        return Document(page_content=content, metadata=metadata)

    async def _get_relevant_documents(self, query: str) -> List[Document]:
        """Retrieve relevant CVE documents for a query.

        This is called by the BaseRetriever.invoke() method.

        Args:
            query: Search query (e.g., "postgresql 13.5 rce", "CVE-2021-32027")

        Returns:
            List of Document objects ranked by relevance
        """
        documents: List[Document] = []

        # First, check if query is a direct CVE ID
        cve_match = re.search(r"CVE-\d{4}-\d{4,7}", query, re.I)
        if cve_match:
            cve_id = cve_match.group(0).upper()
            data = await self._query_nvd_api(cve_id=cve_id)

            if data.get("vulnerabilities"):
                for i, vuln in enumerate(data["vulnerabilities"]):
                    doc = self._format_cve_document(vuln, rank=i)
                    documents.append(doc)
                return documents  # Direct CVE ID match - return immediately

        # Otherwise, do keyword search
        package, version = self._extract_package_and_version(query)
        search_query = f"{package} {version}".strip() if version else package

        data = await self._query_nvd_api(keyword=search_query)

        if data.get("vulnerabilities"):
            for i, vuln in enumerate(data["vulnerabilities"]):
                doc = self._format_cve_document(vuln, rank=i)
                documents.append(doc)

        # Sort by CVSS score (higher = more relevant) then by rank
        documents.sort(
            key=lambda d: (-d.metadata.get("cvss_score", 0), d.metadata.get("rank", 0))
        )

        return documents[:10]  # Return top 10 results

    def invoke(self, input: str, config=None) -> List[Document]:
        """Invoke retriever - BaseRetriever interface."""
        return self.get_relevant_documents(input)

    def get_relevant_documents(self, query: str) -> List[Document]:
        """Synchronous wrapper for BaseRetriever interface."""
        try:
            # Try to use the current event loop if one exists
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Can't use run() on a running loop, this shouldn't happen in practice
                # because BaseRetriever.invoke should not be called from async context
                raise RuntimeError("Cannot call synchronous get_relevant_documents from async context")
        except RuntimeError:
            pass
        return asyncio.run(self._get_relevant_documents(query))


class ThreatIntelRetriever(BaseRetriever):
    """High-level retriever that combines multiple threat intelligence sources."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str = "threat_intel_retriever"
    nvd_retriever: NVDRetriever = Field(default_factory=NVDRetriever)

    def __init__(self, nvd_api_key: Optional[str] = None):
        """Initialize with NVD and other feeds.

        Args:
            nvd_api_key: Optional NVD API key for higher rate limits
        """
        super().__init__(nvd_retriever=NVDRetriever(api_key=nvd_api_key))

    def _get_relevant_documents(self, query: str) -> List[Document]:
        """Route query to appropriate retriever based on content.

        Args:
            query: Search query

        Returns:
            Combined and ranked documents from all sources
        """
        documents: List[Document] = []

        # Check what type of query this is
        is_cve = bool(re.search(r"CVE-\d{4}-\d{4,7}", query, re.I))
        is_ioc = bool(
            re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", query)
            or re.search(r"[a-zA-Z0-9.-]+\.[a-z]{2,}", query)
        )
        is_vuln = any(
            keyword in query.lower()
            for keyword in ["vulnerable", "vuln", "vulnerability", "cve", "exploit"]
        )

        # Query NVD for CVE/vulnerability related queries
        if is_cve or is_vuln or (not is_ioc):
            nvd_docs = self.nvd_retriever.get_relevant_documents(query)
            documents.extend(nvd_docs)

        # TODO: Add OTX retriever for IOC queries
        # if is_ioc:
        #     otx_docs = self.otx_retriever.get_relevant_documents(query)
        #     documents.extend(otx_docs)

        # Rank all documents by relevance
        documents.sort(
            key=lambda d: (
                -d.metadata.get("cvss_score", 0),
                d.metadata.get("rank", 0),
            )
        )

        return documents[:10]

    def invoke(self, input: str, config=None) -> List[Document]:
        """Invoke retriever - BaseRetriever interface."""
        return self.get_relevant_documents(input)

    def get_relevant_documents(self, query: str) -> List[Document]:
        """Get relevant documents for query."""
        return self._get_relevant_documents(query)

    async def async_get_relevant_documents(self, query: str) -> List[Document]:
        """Async version for use in async contexts."""
        return self._get_relevant_documents(query)
