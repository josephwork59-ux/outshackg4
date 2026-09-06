"""Example usage of NVD Retriever for threat intelligence."""

import asyncio
from threat_retriever import NVDRetriever, ThreatIntelRetriever


async def example_direct_cve_lookup():
    """Example 1: Look up a specific CVE by ID."""
    print("=" * 60)
    print("Example 1: Direct CVE Lookup")
    print("=" * 60)

    retriever = NVDRetriever()

    # Query with CVE ID
    docs = await retriever._get_relevant_documents("CVE-2021-32027")

    if docs:
        doc = docs[0]
        print(f"\n✅ Found: {doc.metadata['cve_id']}")
        print(f"Severity: {doc.metadata['severity'].upper()}")
        print(f"CVSS Score: {doc.metadata['cvss_score']}")
        print(f"\nDetails:\n{doc.page_content}")
    else:
        print("❌ No results found")


async def example_package_version_search():
    """Example 2: Search by package name and version."""
    print("\n" + "=" * 60)
    print("Example 2: Package Version Search")
    print("=" * 60)

    retriever = NVDRetriever()

    # Query with package and version
    query = "postgresql 13.5"
    print(f"\nSearching for: {query}")

    docs = await retriever._get_relevant_documents(query)

    if docs:
        print(f"\n✅ Found {len(docs)} vulnerabilities in {query}:")
        for i, doc in enumerate(docs[:3], 1):
            print(f"\n{i}. {doc.metadata['cve_id']}")
            print(f"   Severity: {doc.metadata['severity'].upper()}")
            print(f"   CVSS: {doc.metadata['cvss_score']}")
            print(f"   Packages: {', '.join(doc.metadata['affected_packages'][:2])}")
    else:
        print("❌ No vulnerabilities found")


async def example_generic_search():
    """Example 3: Generic vulnerability search."""
    print("\n" + "=" * 60)
    print("Example 3: Generic Search")
    print("=" * 60)

    retriever = NVDRetriever()

    query = "rce vulnerability"
    print(f"\nSearching for: {query}")

    docs = await retriever._get_relevant_documents(query)

    if docs:
        print(f"\n✅ Found {len(docs)} results:")
        for i, doc in enumerate(docs[:3], 1):
            print(f"\n{i}. {doc.metadata['cve_id']} - {doc.metadata['severity'].upper()}")
            print(f"   CVSS: {doc.metadata['cvss_score']}")
    else:
        print("❌ No results found")


async def example_threat_intel_retriever():
    """Example 4: Use high-level ThreatIntelRetriever."""
    print("\n" + "=" * 60)
    print("Example 4: Threat Intelligence Retriever")
    print("=" * 60)

    retriever = ThreatIntelRetriever()

    queries = [
        "CVE-2021-44228",  # Log4Shell
        "apache struts 2.3.15.1",
        "wordpress plugin vulnerability",
    ]

    for query in queries:
        print(f"\n🔍 Query: {query}")
        docs = retriever.get_relevant_documents(query)
        if docs:
            doc = docs[0]
            print(f"   Result: {doc.metadata['cve_id']} ({doc.metadata['severity'].upper()})")
            print(f"   CVSS: {doc.metadata['cvss_score']}")
        else:
            print("   No results found")


async def example_caching():
    """Example 5: Demonstrate caching behavior."""
    print("\n" + "=" * 60)
    print("Example 5: Caching Behavior")
    print("=" * 60)

    retriever = NVDRetriever(cache_ttl=60)
    query = "postgresql 13.5"

    print(f"\nFirst query for '{query}'...")
    start = asyncio.get_event_loop().time()
    docs1 = await retriever._get_relevant_documents(query)
    time1 = asyncio.get_event_loop().time() - start
    print(f"⏱️  Time: {time1:.2f}s, Results: {len(docs1)}")

    print(f"\nSecond query (should be cached)...")
    start = asyncio.get_event_loop().time()
    docs2 = await retriever._get_relevant_documents(query)
    time2 = asyncio.get_event_loop().time() - start
    print(f"⏱️  Time: {time2:.2f}s, Results: {len(docs2)}")
    print(f"\n✅ Cache improved performance by {(time1/time2 if time2 > 0 else 0):.1f}x")


async def example_integration_with_finding():
    """Example 6: Use in threat detection context."""
    print("\n" + "=" * 60)
    print("Example 6: Integration with Threat Detection")
    print("=" * 60)

    retriever = ThreatIntelRetriever()

    # Simulated finding from log monitor
    finding = {
        "id": "log-001",
        "title": "Remote Code Execution Attempt",
        "description": "Potential RCE exploit attempt on apache struts",
        "evidence": ["POST /admin.action", "payload contains ognl expression"],
    }

    print(f"\n📋 Finding: {finding['title']}")
    print(f"   Description: {finding['description']}")

    # Query threat intel for this finding
    query = f"{finding['title']} {finding['description']}"
    docs = retriever.get_relevant_documents(query)

    if docs:
        print(f"\n✅ Enriched with threat intelligence:")
        for i, doc in enumerate(docs[:2], 1):
            print(f"\n   {i}. {doc.metadata['cve_id']}")
            print(f"      Severity: {doc.metadata['severity'].upper()}")
            print(f"      CVSS: {doc.metadata['cvss_score']}")
            print(f"      Affected: {', '.join(doc.metadata['affected_packages'][:3])}")
    else:
        print("\n⚠️ No threat intelligence found")


async def main():
    """Run all examples."""
    print("\n" + "🔐 NVD RETRIEVER EXAMPLES".center(60, "="))

    try:
        await example_direct_cve_lookup()
        await example_package_version_search()
        await example_generic_search()
        await example_threat_intel_retriever()
        await example_caching()
        await example_integration_with_finding()

        print("\n" + "=" * 60)
        print("✅ All examples completed successfully!")
        print("=" * 60)

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
