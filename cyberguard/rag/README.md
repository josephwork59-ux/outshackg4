# RAG Layer - Threat Intelligence Retrieval

This module provides Retrieval-Augmented Generation (RAG) capabilities for real-time threat intelligence in CyberGuard.

## Overview

The RAG layer queries multiple threat intelligence sources to enrich security findings with real-time data:

- **CVE Data**: National Vulnerability Database (NVD) API
- **IOC Reputation**: AlienVault OTX, VirusTotal, abuse.ch
- **Malware URLs**: URLhaus
- **Threat Actors**: MITRE ATT&CK framework

## Quick Start

### Basic Usage - Query NVD for CVEs

```python
from cyberguard.rag import NVDRetriever
import asyncio

async def example():
    retriever = NVDRetriever()
    
    # Query by CVE ID
    docs = await retriever._get_relevant_documents("CVE-2021-32027")
    for doc in docs:
        print(f"CVE: {doc.metadata['cve_id']}")
        print(f"CVSS: {doc.metadata['cvss_score']}")
        print(f"Severity: {doc.metadata['severity']}")
    
    # Query by package name
    docs = await retriever._get_relevant_documents("postgresql 13.5")
    
    # Generic vulnerability search
    docs = await retriever._get_relevant_documents("log4j rce")

asyncio.run(example())
```

### Using ThreatIntelRetriever (High-Level)

```python
from cyberguard.rag import ThreatIntelRetriever

retriever = ThreatIntelRetriever()

# Synchronous interface
docs = retriever.get_relevant_documents("CVE-2021-44228")

for doc in docs:
    print(doc.page_content)  # Full CVE details
    print(doc.metadata)      # Structured data
```

## Components

### 1. NVDRetriever

Queries the National Vulnerability Database (NVD) API for CVE information.

**Features:**
- Direct CVE ID lookup (e.g., "CVE-2021-32027")
- Package name + version search (e.g., "postgresql 13.5")
- Keyword-based search (e.g., "rce vulnerability")
- Automatic caching with configurable TTL
- Rate limiting enforcement (1 request per 0.6 seconds without API key)
- Sorting by CVSS score and relevance

**API Limits:**
- Without API key: 5 requests per 30 minutes
- With API key: 50 requests per 30 minutes

**Getting an API Key (Free):**
Visit https://nvd.nist.gov/developers/request-an-api-key

```python
# Use with API key
retriever = NVDRetriever(api_key="your-nvd-api-key")
```

### 2. ThreatIntelRetriever

High-level retriever that routes queries to appropriate sources.

**Query Routing:**
- CVE IDs → NVD retriever
- IP addresses → OTX retriever (future)
- Domains → OTX retriever (future)
- File hashes → VirusTotal, abuse.ch (future)

### 3. Feed Providers (feeds.py)

Modular threat intelligence feed implementations:

#### OTXFeed - AlienVault Open Threat Exchange

```python
from cyberguard.rag.feeds import OTXFeed

otx = OTXFeed(api_key="your-otx-api-key")  # Free tier available

# Query IP reputation
ip_data = await otx.query_ip("204.48.28.31")
print(ip_data["reputation"])  # -50 = malicious
print(ip_data["pulse_info"]["pulses"])  # Campaigns

# Query domain
domain_data = await otx.query_domain("example.com")

# Query file hash
hash_data = await otx.query_hash("d41d8cd98f00b204e9800998ecf8427e")

await otx.close()
```

#### VirusTotalFeed

```python
from cyberguard.rag.feeds import VirusTotalFeed

vt = VirusTotalFeed(api_key="your-virustotal-api-key")
vt_data = await vt.query_domain("example.com")
await vt.close()
```

#### URLhausFeed

```python
from cyberguard.rag.feeds import URLhausFeed

urlhaus = URLhausFeed()  # No API key required
url_data = await urlhaus.query_url("http://example.com/malware.exe")
await urlhaus.close()
```

## Document Format

Documents returned by retrievers are LangChain `Document` objects with:

**page_content** (string):
```
CVE: CVE-2021-32027
Severity: CRITICAL
CVSS Score: 9.8

Description:
Buffer overrun in PostgreSQL...

Affected Packages:
  • postgresql:13.5
  • postgresql:13.0
  
References:
  • https://nvd.nist.gov/vuln/detail/CVE-2021-32027
  • https://www.postgresql.org/support/security/
```

**metadata** (dict):
```python
{
    "source": "nvd",
    "cve_id": "CVE-2021-32027",
    "cvss_score": 9.8,
    "severity": "critical",
    "published_date": "2021-05-13T00:00:00Z",
    "last_modified": "2021-05-13T00:00:00Z",
    "affected_packages": ["postgresql:13.5", "postgresql:13.0"],
    "rank": 0,
    "references": ["https://nvd.nist.gov/...", "..."]
}
```

## Integration with LangGraph

Use retrievers in LangGraph nodes for threat enrichment:

```python
from langgraph.graph import StateGraph
from cyberguard.rag import ThreatIntelRetriever

class GraphState(TypedDict):
    findings: List[dict]
    enrichment_context: dict

retriever = ThreatIntelRetriever()

def enrich_findings_node(state: GraphState) -> GraphState:
    """Enrich findings with threat intelligence."""
    findings = state["findings"]
    
    for finding in findings:
        # Create query from finding
        query = f"{finding['title']} {finding['description']}"
        
        # Retrieve threat intel
        docs = retriever.get_relevant_documents(query)
        
        # Attach to finding
        finding['threat_intel'] = [
            {
                'cve_id': doc.metadata['cve_id'],
                'cvss': doc.metadata['cvss_score'],
                'severity': doc.metadata['severity'],
                'references': doc.metadata['references']
            }
            for doc in docs
        ]
    
    state['findings'] = findings
    return state

# Add to graph
graph = StateGraph(GraphState)
graph.add_node("enrich", enrich_findings_node)
```

## Caching

NVD queries are cached in-memory to improve performance:

```python
# 1 hour cache (default)
retriever = NVDRetriever()

# Custom cache TTL
retriever = NVDRetriever(cache_ttl=7200)  # 2 hours

# Clear cache
retriever.cache.clear()

# Check cache stats
print(len(retriever.cache.cache))  # Number of cached queries
```

**Cache Key:** MD5 hash of the query string
**Storage:** In-memory dictionary
**Eviction:** Time-based (TTL)

## Rate Limiting

NVD API enforces strict rate limits:

- **Without API key:** 5 requests per 30 minutes
- **With API key:** 50 requests per 30 minutes

The retriever automatically enforces delays between requests:

```python
# Without API key: minimum 0.6 seconds between requests
# With API key: allows faster requests

retriever = NVDRetriever(api_key="your-key")
```

## Examples

### Example 1: Security Finding Enrichment

```python
finding = {
    "title": "Apache Struts 2.3.15.1 RCE",
    "description": "Remote code execution via OGNL injection",
    "package": "apache-struts",
    "version": "2.3.15.1"
}

retriever = ThreatIntelRetriever()
query = f"{finding['package']} {finding['version']} rce"
docs = retriever.get_relevant_documents(query)

if docs:
    cve = docs[0].metadata
    print(f"CVE: {cve['cve_id']}")
    print(f"CVSS: {cve['cvss_score']}")
    print(f"Severity: {cve['severity']}")
    # Use in incident response planning...
```

### Example 2: Real-Time Threat Detection

```python
async def detect_threats(log_entry):
    retriever = ThreatIntelRetriever()
    
    # Extract indicators from log
    extracted_cves = extract_cves(log_entry)
    extracted_ips = extract_ips(log_entry)
    
    for cve_id in extracted_cves:
        docs = retriever.get_relevant_documents(cve_id)
        if docs and docs[0].metadata['severity'] == 'critical':
            alert_incident_response(cve_id, docs[0])
    
    for ip in extracted_ips:
        docs = retriever.get_relevant_documents(ip)
        if docs:
            check_ioc_reputation(ip, docs[0])
```

### Example 3: Batch Enrichment

```python
async def enrich_findings_batch(findings: List[dict]):
    retriever = ThreatIntelRetriever()
    
    enriched = []
    for finding in findings:
        query = f"{finding['category']} {finding['title']}"
        docs = retriever.get_relevant_documents(query)
        
        finding['threat_intel'] = [
            {
                'source': doc.metadata['source'],
                'cve': doc.metadata.get('cve_id'),
                'cvss': doc.metadata.get('cvss_score'),
                'references': doc.metadata.get('references', [])
            }
            for doc in docs[:3]  # Top 3 results
        ]
        enriched.append(finding)
    
    return enriched
```

## Environment Variables

Optional configuration via environment:

```bash
# NVD API Key (optional, enables higher rate limits)
export NVD_API_KEY="your-nvd-api-key"

# OTX API Key (optional)
export OTX_API_KEY="your-otx-api-key"

# VirusTotal API Key (optional)
export VIRUSTOTAL_API_KEY="your-vt-api-key"
```

## Performance Considerations

| Optimization | Method |
|--------------|--------|
| **Query latency** | Enable caching (1 hour default) |
| **Rate limit hits** | Use API keys for higher limits |
| **Batch queries** | Combine multiple findings in single query |
| **Async processing** | Use `astream_events` in LangGraph |
| **Feed updates** | Schedule periodic refreshes (6-hourly) |

## Testing

Run the examples:

```bash
cd cyberguard/rag
python example_nvd_usage.py
```

Expected output:
```
============================================================
Example 1: Direct CVE Lookup
============================================================

✅ Found: CVE-2021-32027
Severity: CRITICAL
CVSS Score: 9.8

Details:
CVE: CVE-2021-32027
...
```

## Troubleshooting

**"Rate limit exceeded"**
- Add NVD API key for higher limits
- Increase cache TTL to reduce requests

**"No results found"**
- Verify package name spelling
- Try different search terms
- Check NVD API status

**"Connection timeout"**
- Verify internet connectivity
- Check NVD API availability (nvd.nist.gov)
- Increase client timeout: `NVDRetriever(timeout=60)`

## Future Enhancements

- [ ] Full OTX integration for IOC queries
- [ ] VirusTotal integration
- [ ] URLhaus malware URL lookup
- [ ] MITRE ATT&CK framework queries
- [ ] Local vector database (Pinecone, Weaviate)
- [ ] Semantic similarity for fuzzy matching
- [ ] Redis caching for distributed deployments
- [ ] Prometheus metrics for monitoring
- [ ] OpenTelemetry tracing

## References

- **NVD API**: https://nvd.nist.gov/developers
- **OTX**: https://otx.alienvault.com
- **VirusTotal**: https://www.virustotal.com/
- **URLhaus**: https://urlhaus.abuse.ch/
- **abuse.ch**: https://abuse.ch/
- **MITRE ATT&CK**: https://attack.mitre.org/
