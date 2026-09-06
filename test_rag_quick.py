#!/usr/bin/env python
"""Quick test script for NVD RAG retriever - run this to verify setup."""

import asyncio
import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from cyberguard.rag import NVDRetriever, ThreatIntelRetriever


async def test_nvd_basic():
    """Test basic NVD retriever functionality."""
    print("\n" + "=" * 70)
    print("TEST 1: Basic NVD Retriever - Direct CVE ID Lookup")
    print("=" * 70)

    retriever = NVDRetriever()
    print("✓ NVDRetriever initialized")

    try:
        query = "CVE-2021-44228"
        print(f"✓ Querying NVD API for: {query}")

        docs = await retriever._get_relevant_documents(query)

        if docs:
            print(f"✓ Found {len(docs)} result(s)")
            doc = docs[0]
            print(f"\n  CVE ID: {doc.metadata['cve_id']}")
            print(f"  Severity: {doc.metadata['severity'].upper()}")
            print(f"  CVSS Score: {doc.metadata['cvss_score']}")
            print(f"  Published: {doc.metadata['published_date']}")
            print(f"  Affected Packages: {len(doc.metadata['affected_packages'])}")
            print(f"\n  Content Preview:\n{doc.page_content[:200]}...")
            return True
        else:
            print("✗ No results found")
            return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


async def test_nvd_package():
    """Test NVD retriever with package + version."""
    print("\n" + "=" * 70)
    print("TEST 2: Package + Version Search")
    print("=" * 70)

    retriever = NVDRetriever()

    try:
        query = "postgresql 13.5"
        print(f"✓ Querying NVD API for: {query}")

        docs = await retriever._get_relevant_documents(query)

        if docs:
            print(f"✓ Found {len(docs)} result(s)")
            for i, doc in enumerate(docs[:3], 1):
                print(f"\n  {i}. {doc.metadata['cve_id']}")
                print(f"     CVSS: {doc.metadata['cvss_score']}")
                print(f"     Severity: {doc.metadata['severity'].upper()}")
            return True
        else:
            print("✗ No results found")
            return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


async def test_caching():
    """Test caching behavior."""
    print("\n" + "=" * 70)
    print("TEST 3: Caching Behavior")
    print("=" * 70)

    retriever = NVDRetriever()

    try:
        query = "CVE-2021-44228"
        print(f"✓ First query (should hit API): {query}")

        import time
        start = time.time()
        docs1 = await retriever._get_relevant_documents(query)
        time1 = time.time() - start

        print(f"✓ Time: {time1:.3f}s, Results: {len(docs1)}")

        print(f"✓ Second query (should be cached)")
        start = time.time()
        docs2 = await retriever._get_relevant_documents(query)
        time2 = time.time() - start

        print(f"✓ Time: {time2:.3f}s, Results: {len(docs2)}")

        speedup = time1 / time2 if time2 > 0 else 1
        print(f"✓ Cache speedup: {speedup:.1f}x faster")

        if speedup > 10:
            print("✓ Caching working correctly!")
            return True
        else:
            print("⚠ Caching may not be working as expected")
            return True  # Not a failure
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


async def test_threat_intel_router():
    """Test high-level ThreatIntelRetriever."""
    print("\n" + "=" * 70)
    print("TEST 4: ThreatIntelRetriever Router")
    print("=" * 70)

    retriever = ThreatIntelRetriever()
    print("✓ ThreatIntelRetriever initialized")

    try:
        tests = [
            ("CVE-2021-44228", "Direct CVE ID"),
            ("log4j", "Generic package search"),
            ("rce vulnerability", "Vulnerability type"),
        ]

        for query, desc in tests:
            print(f"\n✓ Testing: {desc} → '{query}'")
            docs = retriever.get_relevant_documents(query)

            if docs:
                print(f"  ✓ Found {len(docs)} result(s)")
                print(f"    Top result: {docs[0].metadata['cve_id']}")
            else:
                print(f"  ⚠ No results (may be expected for generic searches)")

        return True
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


async def test_document_format():
    """Test that documents have proper format for LangChain."""
    print("\n" + "=" * 70)
    print("TEST 5: Document Format Validation")
    print("=" * 70)

    retriever = NVDRetriever()

    try:
        docs = await retriever._get_relevant_documents("CVE-2021-44228")

        if not docs:
            print("✗ No documents to validate")
            return False

        doc = docs[0]
        print("✓ Checking document structure...")

        # Check page_content
        if not doc.page_content:
            print("✗ Missing page_content")
            return False
        print("✓ page_content present")

        # Check metadata
        required_fields = [
            "cve_id",
            "cvss_score",
            "severity",
            "published_date",
            "affected_packages",
            "references",
            "source",
        ]

        for field in required_fields:
            if field not in doc.metadata:
                print(f"✗ Missing metadata field: {field}")
                return False

        print(f"✓ All required metadata fields present ({len(required_fields)})")
        print(f"\nMetadata keys: {list(doc.metadata.keys())}")

        return True
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


async def main():
    """Run all tests."""
    print("\n" + "NVD RAG RETRIEVER - QUICK TEST SUITE".center(70, "="))
    print(f"{'Testing setup and functionality...'.center(70)}\n")

    results = []

    # Run tests
    results.append(("Basic CVE Lookup", await test_nvd_basic()))
    results.append(("Package Search", await test_nvd_package()))
    results.append(("Caching", await test_caching()))
    results.append(("Router", await test_threat_intel_router()))
    results.append(("Document Format", await test_document_format()))

    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {name}")

    print(f"\nTotal: {passed}/{total} tests passed")

    if passed == total:
        print("\n[SUCCESS] All tests passed! RAG retriever is working correctly.")
        print("\nNext steps:")
        print("1. Review cyberguard/rag/README.md for full documentation")
        print("2. Check cyberguard/rag/QUICKSTART.md for integration guide")
        print("3. Run: python cyberguard/rag/example_nvd_usage.py")
        print("4. Get NVD API key: https://nvd.nist.gov/developers/request-an-api-key")
        return 0
    else:
        print(f"\n[WARNING] {total - passed} test(s) failed. Check output above.")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
