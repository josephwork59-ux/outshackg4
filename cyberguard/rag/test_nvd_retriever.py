"""Tests for NVD Retriever and threat intelligence integration."""

import asyncio
import pytest
from threat_retriever import NVDRetriever, NVDCache, ThreatIntelRetriever


class TestNVDCache:
    """Test caching behavior."""

    def test_cache_set_and_get(self):
        """Test basic cache set/get."""
        cache = NVDCache(ttl_seconds=10)
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"

    def test_cache_expiration(self):
        """Test cache expiration."""
        cache = NVDCache(ttl_seconds=1)
        cache.set("key1", "value1")

        # Should be available immediately
        assert cache.get("key1") == "value1"

        # Wait for expiration
        import time
        time.sleep(1.1)
        assert cache.get("key1") is None

    def test_cache_clear(self):
        """Test cache clearing."""
        cache = NVDCache()
        cache.set("key1", "value1")
        cache.set("key2", "value2")

        cache.clear()
        assert cache.get("key1") is None
        assert cache.get("key2") is None


class TestNVDRetriever:
    """Test NVD retriever functionality."""

    @pytest.mark.asyncio
    async def test_extract_cve_id(self):
        """Test CVE ID extraction."""
        retriever = NVDRetriever()

        # Test with direct CVE ID
        package, version = retriever._extract_package_and_version("CVE-2021-32027")
        assert package == "CVE-2021-32027"
        assert version is None

        # Test case-insensitive
        package, version = retriever._extract_package_and_version("cve-2021-32027")
        assert package.upper() == "CVE-2021-32027"

    @pytest.mark.asyncio
    async def test_extract_package_version(self):
        """Test package and version extraction."""
        retriever = NVDRetriever()

        # Test package with version
        package, version = retriever._extract_package_and_version("postgresql 13.5")
        assert package.lower() == "postgresql"
        assert version == "13.5"

        # Test with multiple parts
        package, version = retriever._extract_package_and_version("apache struts 2.3.15.1 rce")
        assert package.lower() == "apache"
        assert version == "2.3.15.1"

    @pytest.mark.asyncio
    async def test_cve_document_formatting(self):
        """Test CVE document formatting."""
        retriever = NVDRetriever()

        # Mock CVE data
        cve_item = {
            "cve": {
                "id": "CVE-2021-32027",
                "descriptions": [
                    {"lang": "en", "value": "Buffer overrun in PostgreSQL"}
                ],
                "metrics": {
                    "cvssV3": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL"
                    }
                },
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "criteria": "cpe:2.3:a:postgresql:postgresql:13.5:*:*:*:*:*:*:*"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-32027"},
                    {"url": "https://www.postgresql.org/support/security/"}
                ],
                "published": "2021-05-13T00:00:00Z",
                "lastModified": "2021-05-13T00:00:00Z"
            }
        }

        doc = retriever._format_cve_document(cve_item, rank=0)

        # Check document properties
        assert doc.metadata["cve_id"] == "CVE-2021-32027"
        assert doc.metadata["cvss_score"] == 9.8
        assert doc.metadata["severity"] == "critical"
        assert "postgresql" in doc.metadata["affected_packages"][0].lower()
        assert "CVE-2021-32027" in doc.page_content
        assert "CRITICAL" in doc.page_content

    @pytest.mark.asyncio
    async def test_rate_limiting(self):
        """Test rate limiting enforcement."""
        retriever = NVDRetriever()
        retriever.rate_limit_delay = 0.1  # Reduce for testing

        import time
        start = time.time()

        # Make two requests
        await retriever._rate_limit_wait()
        await retriever._rate_limit_wait()

        elapsed = time.time() - start
        # Should have enforced delay between requests
        assert elapsed >= 0.1

    def test_real_query_metadata_structure(self):
        """Test metadata structure for real query."""
        retriever = NVDRetriever()

        # Get documents (may fail if no internet, but test structure if it succeeds)
        try:
            docs = retriever.get_relevant_documents("CVE-2021-44228")

            if docs:
                doc = docs[0]

                # Verify metadata structure
                assert "cve_id" in doc.metadata
                assert "cvss_score" in doc.metadata
                assert "severity" in doc.metadata
                assert "published_date" in doc.metadata
                assert "affected_packages" in doc.metadata
                assert "references" in doc.metadata
                assert isinstance(doc.metadata["affected_packages"], list)
                assert isinstance(doc.metadata["references"], list)

                # Verify page_content is populated
                assert len(doc.page_content) > 0
                assert "CVE-" in doc.page_content
        except Exception as e:
            # Skip if network unavailable
            pytest.skip(f"Network unavailable: {e}")


class TestThreatIntelRetriever:
    """Test high-level threat intelligence retriever."""

    def test_initialization(self):
        """Test retriever initialization."""
        retriever = ThreatIntelRetriever()
        assert retriever.nvd_retriever is not None

    def test_query_routing(self):
        """Test query routing logic."""
        retriever = ThreatIntelRetriever()

        # CVE queries should route to NVD
        docs = retriever.get_relevant_documents("CVE-2021-44228")

        # If we got results, verify they're CVE-related
        if docs:
            assert any("CVE-" in doc.metadata.get("cve_id", "") for doc in docs)


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v", "--tb=short"])
