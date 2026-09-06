# Quick Start: NVD RAG Retriever for CyberGuard

Get up and running with the NVD Retriever in 5 minutes.

## Step 1: Get NVD API Key (Optional but Recommended)

1. Visit: https://nvd.nist.gov/developers/request-an-api-key
2. Enter your email and submit
3. Check your email for the API key
4. Set as environment variable:

```bash
export NVD_API_KEY="your-api-key-here"
```

**Why?** 
- Without key: 5 requests per 30 minutes
- With key: 50 requests per 30 minutes

## Step 2: Basic Usage

```python
from cyberguard.rag import NVDRetriever

# Initialize retriever
retriever = NVDRetriever(api_key="your-api-key")

# Query by CVE ID
docs = retriever.get_relevant_documents("CVE-2021-44228")
print(f"Found: {docs[0].metadata['cve_id']}")
print(f"CVSS Score: {docs[0].metadata['cvss_score']}")

# Query by package + version
docs = retriever.get_relevant_documents("postgresql 13.5")
for doc in docs[:3]:
    print(f"- {doc.metadata['cve_id']} (CVSS {doc.metadata['cvss_score']})")

# Generic search
docs = retriever.get_relevant_documents("apache struts rce")
```

## Step 3: Run Example

```bash
cd cyberguard/rag
python example_nvd_usage.py
```

Expected output:
```
============================================================
Example 1: Direct CVE Lookup
============================================================

✅ Found: CVE-2021-44228
Severity: CRITICAL
CVSS Score: 10.0

Details:
CVE: CVE-2021-44228
...
```

## Step 4: Integrate with Threat Intel Agent

Update `cyberguard/agents/threat_intel.py` to use RAG:

```python
from cyberguard.rag import ThreatIntelRetriever

class ThreatIntelAgent(Agent):
    def __init__(self, feed=None):
        self.feed = feed or BundledFeed()
        self.rag = ThreatIntelRetriever()  # Add this
    
    def _enrich(self, findings, target):
        notes = []
        
        for finding in findings:
            # NEW: Get threat intel from RAG
            query = f"{finding.category} {finding.title}"
            rag_docs = self.rag.get_relevant_documents(query)
            
            if rag_docs:
                for doc in rag_docs[:3]:
                    # Attach to enrichment
                    finding.enrichment.setdefault("rag_threat_intel", []).append({
                        "cve_id": doc.metadata["cve_id"],
                        "cvss_score": doc.metadata["cvss_score"],
                        "severity": doc.metadata["severity"],
                        "affected_packages": doc.metadata["affected_packages"],
                    })
        
        return AgentResult(self.name, findings, "ok", notes)
```

## Step 5: Test in Streamlit

Add to threat intelligence page:

```python
# pages/3_Threat_Intelligence.py
from cyberguard.rag import ThreatIntelRetriever

retriever = ThreatIntelRetriever()

st.subheader("🔍 Query Threat Intelligence")
query = st.text_input("Search CVE or vulnerability", value="log4j")

if st.button("Search"):
    with st.spinner("Searching NVD..."):
        docs = retriever.get_relevant_documents(query)
        
        if docs:
            for doc in docs[:5]:
                with st.expander(f"{doc.metadata['cve_id']} - CVSS {doc.metadata['cvss_score']}"):
                    st.write(doc.page_content)
                    st.json(doc.metadata)
        else:
            st.warning("No vulnerabilities found")
```

## Step 6: Use in LangGraph (Future)

```python
from langgraph.graph import StateGraph
from cyberguard.rag import ThreatIntelRetriever

retriever = ThreatIntelRetriever()

def enrich_findings_node(state):
    """Enrich findings with RAG."""
    for finding in state["findings"]:
        query = f"{finding['title']} {finding['description']}"
        docs = retriever.get_relevant_documents(query)
        finding['threat_intel'] = [d.metadata for d in docs[:3]]
    return state

graph.add_node("enrichment", enrich_findings_node)
```

## Common Queries

### Query CVE by ID
```python
docs = retriever.get_relevant_documents("CVE-2021-32027")
```

### Query Package Vulnerability
```python
docs = retriever.get_relevant_documents("postgresql 13.5")
docs = retriever.get_relevant_documents("apache struts 2.3.15")
docs = retriever.get_relevant_documents("log4j 2.14.1")
```

### Query Vulnerability Type
```python
docs = retriever.get_relevant_documents("rce remote code execution")
docs = retriever.get_relevant_documents("sql injection")
docs = retriever.get_relevant_documents("buffer overflow")
```

## Performance Tips

### Enable Caching
```python
# Cache results for 2 hours
retriever = NVDRetriever(api_key="key", cache_ttl=7200)
```

### Use API Key
```python
# Increases rate limit from 5 to 50 req/30 min
retriever = NVDRetriever(api_key=os.getenv("NVD_API_KEY"))
```

### Batch Queries
```python
# Instead of querying one-by-one:
# Good: Create combined query
query = "postgresql 13.5 rce"
docs = retriever.get_relevant_documents(query)

# Avoid: Multiple separate queries
docs1 = retriever.get_relevant_documents("postgresql")
docs2 = retriever.get_relevant_documents("rce")
```

## Troubleshooting

### "Rate limit exceeded"

```python
# Solution 1: Add API key
retriever = NVDRetriever(api_key="your-key")

# Solution 2: Increase cache TTL
retriever = NVDRetriever(cache_ttl=7200)

# Solution 3: Batch queries
```

### "No results found"

```python
# Try different search terms
docs = retriever.get_relevant_documents("postgresql")  # Generic
docs = retriever.get_relevant_documents("postgresql 13.5 vulnerability")  # Specific
docs = retriever.get_relevant_documents("CVE-2021-32027")  # Direct CVE ID
```

### "Connection timeout"

```python
# Verify internet connectivity
# Check NVD status: https://nvd.nist.gov/
# Retry after a few seconds
```

## Next Steps

1. ✅ Run examples
2. ✅ Integrate with threat_intel agent
3. ✅ Test in Streamlit UI
4. ⬜️ Add OTX integration for IOC queries
5. ⬜️ Build LangGraph threat detection graph
6. ⬜️ Add real-time streaming to dashboard

## Full Documentation

See [README.md](README.md) for comprehensive documentation including:
- Advanced usage patterns
- OTX, VirusTotal, URLhaus integration
- LangGraph integration examples
- Performance optimization
- Testing and troubleshooting
