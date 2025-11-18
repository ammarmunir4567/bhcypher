# LangChain Agent Architecture for Report Generation

## Overview

The report generation system now uses a **LangChain ReAct Agent** with specialized tools for security analysis. This agentic approach provides:

- **Reasoning capabilities** - The agent thinks through the analysis step-by-step
- **Tool usage** - Access to specialized security analysis tools
- **Extensibility** - Easy to add new tools and capabilities
- **Reliability** - Fallback to direct API if agent fails

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Security Scan JSON                       │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              parse_scan() - Extract Data                    │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│          generate_full_report_with_gemini()                 │
│                  use_agent=True                             │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│               🤖 LangChain ReAct Agent                      │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Gemini LLM (gemini-2.5-flash)                       │  │
│  │  - Temperature: 0.2 (consistent analysis)            │  │
│  │  - Max Iterations: 15                                │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Agent Tools:                                         │  │
│  │  1. analyze_vulnerabilities                          │  │
│  │     → Categorize by severity                         │  │
│  │  2. calculate_risk_score                             │  │
│  │     → Compute weighted risk (0-10)                   │  │
│  │  3. generate_remediation                             │  │
│  │     → Create action plans per CVE                    │  │
│  │  4. get_security_context                             │  │
│  │     → Retrieve best practices                        │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  Agent Workflow:                                            │
│  ┌────────────────────────────────────────┐                │
│  │ 1. Analyze vulnerabilities → severity  │                │
│  │ 2. Calculate overall risk score        │                │
│  │ 3. For each critical/high CVE:         │                │
│  │    - Generate specific remediation     │                │
│  │ 4. Get security best practices         │                │
│  │ 5. Compile JSON report                 │                │
│  └────────────────────────────────────────┘                │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              Structured JSON Report                         │
│  {                                                          │
│    "executive_summary": "...",                              │
│    "system_overview": "...",                                │
│    "findings": [...],                                       │
│    "recommendations": "...",                                │
│    "risk_score": 7.5,                                       │
│    "risk_level": "High"                                     │
│  }                                                          │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│           render_report() - Jinja2 + WeasyPrint             │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
               HTML + PDF Report
```

---

## Agent Tools

### 1. `analyze_vulnerabilities`

**Purpose**: Categorize vulnerabilities by severity using keyword analysis.

**Input**: JSON string with vulnerability array
```json
[
  {"cve_id": "CVE-2023-1234", "description": "Remote code execution in..."},
  ...
]
```

**Output**: Severity breakdown
```json
{
  "total": 10,
  "critical": {"count": 2, "cves": ["CVE-2023-1234", ...]},
  "high": {"count": 5, "cves": [...]},
  "medium": {"count": 2, "cves": [...]},
  "low": {"count": 1, "cves": [...]}
}
```

**Detection Keywords**:
- **Critical**: "remote code execution", "rce", "arbitrary code", "privilege escalation"
- **High**: "denial of service", "dos", "authentication bypass", "sql injection"
- **Medium**: "information disclosure", "cross-site scripting", "xss"
- **Low**: Everything else

---

### 2. `calculate_risk_score`

**Purpose**: Calculate weighted risk score (0-10) from severity breakdown.

**Input**: Severity breakdown JSON

**Output**: Risk score and level
```json
{
  "risk_score": 7.85,
  "risk_level": "High",
  "details": {
    "critical_vulns": 2,
    "high_vulns": 5,
    "medium_vulns": 2,
    "low_vulns": 1,
    "total_vulns": 10
  }
}
```

**Weights**:
- Critical: 10.0
- High: 7.0
- Medium: 4.0
- Low: 1.0

**Risk Levels**:
- `8.0+` → Critical
- `6.0-7.9` → High
- `4.0-5.9` → Medium
- `<4.0` → Low

---

### 3. `generate_remediation`

**Purpose**: Generate specific remediation steps for a CVE.

**Input**: CVE data JSON
```json
{
  "cve_id": "CVE-2023-1234",
  "description": "Remote code execution vulnerability...",
  "severity": "critical"
}
```

**Output**: Actionable recommendations
```json
{
  "cve_id": "CVE-2023-1234",
  "priority": "Immediate (24-48 hours)",
  "recommendations": [
    "Apply vendor security patch immediately",
    "Isolate affected systems from network if patch unavailable",
    "Implement network segmentation and firewall rules",
    "Monitor for exploitation attempts in logs"
  ],
  "references": [
    "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
    "NIST SP 800-53: Security Controls",
    "OWASP Top 10",
    "MITRE ATT&CK Framework"
  ]
}
```

**Priority Mapping**:
- Critical/High → "Immediate (24-48 hours)"
- Medium → "High (1 week)"
- Low → "Medium (2-4 weeks)"

---

### 4. `get_security_context`

**Purpose**: Retrieve security best practices and guidelines.

**Input**: Query string (e.g., "patch management", "incident response")

**Output**: Relevant security context and frameworks

**Knowledge Areas**:
- Patch Management
- Incident Response
- Vulnerability Assessment
- General Security Principles

---

## ReAct Agent Workflow

The agent uses the **ReAct (Reasoning + Acting)** pattern:

```
Thought: I need to analyze the vulnerabilities first
Action: analyze_vulnerabilities
Action Input: [vulnerabilities JSON]
Observation: [severity breakdown]

Thought: Now I should calculate the overall risk score
Action: calculate_risk_score
Action Input: [severity breakdown]
Observation: [risk score: 7.85, level: High]

Thought: I need remediation for each critical CVE
Action: generate_remediation
Action Input: {"cve_id": "CVE-2023-1234", ...}
Observation: [remediation steps]

... (repeats for each critical/high CVE)

Thought: I should get best practices context
Action: get_security_context
Action Input: "patch management"
Observation: [best practices]

Thought: I now have all the information to compile the report
Final Answer: [Complete JSON report]
```

---

## Configuration

### Environment Variables

```bash
# Agent Configuration
USE_AGENT=true                    # Enable/disable agent (default: true)
AGENT_VERBOSE=true                # Show agent reasoning (default: true)
AGENT_MAX_ITERATIONS=15           # Max agent steps (default: 15)

# Gemini Configuration
GEMINI_MODEL=gemini-2.5-flash     # LLM model
GEMINI_API_KEY=your_api_key_here  # Required
```

### In Code

```python
from app.core.config import settings

# Use agent by default
settings.use_agent = True

# Or disable for direct API call
settings.use_agent = False
```

---

## Usage Examples

### Basic Usage (Automatic Agent Selection)

```python
from app.services.report_service import generate_report_from_scan

# Automatically uses agent if USE_AGENT=true
html, pdf, summary, report_data = generate_report_from_scan(scan_json)
```

### Explicit Agent Control

```python
from app.services.ai_service import generate_full_report_with_gemini
from app.services.report_service import parse_scan

parsed_scan = parse_scan(scan_json)

# Use agent
report_agent = generate_full_report_with_gemini(parsed_scan, use_agent=True)

# Use direct API
report_direct = generate_full_report_with_gemini(parsed_scan, use_agent=False)
```

### Testing the Agent

```bash
# Run the test script
python test_agent.py
```

---

## Advantages of Agent Approach

### 1. **Structured Reasoning**
- Agent thinks through the analysis step-by-step
- Clear decision-making process visible in logs
- Better handling of complex scenarios

### 2. **Tool Specialization**
- Each tool focuses on one task
- Easier to test and maintain
- Can be improved independently

### 3. **Extensibility**
- Easy to add new tools (e.g., CVE database lookup, exploit check)
- Can integrate external APIs
- Modular architecture

### 4. **Reliability**
- Automatic fallback to direct API if agent fails
- Multiple attempts with error handling
- Graceful degradation

### 5. **Transparency**
- Agent reasoning visible when verbose=true
- See which tools are used and why
- Better debugging and optimization

---

## Adding New Tools

To add a new tool to the agent:

1. **Define the tool function** in `app/services/agent_service.py`:

```python
def my_new_tool(input_data: str) -> str:
    """
    Tool description here.
    
    Args:
        input_data: Description of input
    
    Returns:
        Description of output
    """
    # Tool implementation
    result = do_something(input_data)
    return json.dumps(result)
```

2. **Register the tool** in `create_security_agent()`:

```python
tools = [
    # ... existing tools ...
    Tool(
        name="my_new_tool",
        func=my_new_tool,
        description="""
        Clear description of what this tool does, when to use it,
        expected input format, and what it returns.
        """
    )
]
```

3. **Update the agent prompt** to mention the new tool in the workflow section.

---

## Fallback Mechanism

The system has multiple fallback layers:

```
1. Try LangChain Agent (if enabled)
   ↓ (on failure)
2. Try Direct Gemini API call
   ↓ (on failure)
3. Generate stub report from scan data
```

This ensures you always get a report, even if AI services are unavailable.

---

## Performance Considerations

### Agent vs Direct API

| Aspect | Agent | Direct API |
|--------|-------|------------|
| **Latency** | Higher (multiple API calls) | Lower (single call) |
| **Quality** | Better (structured analysis) | Good |
| **Cost** | Higher (more tokens) | Lower |
| **Transparency** | High (see reasoning) | Low |
| **Extensibility** | High | Limited |

### Recommendations

- **Use Agent** for production reports requiring high quality
- **Use Direct API** for quick previews or testing
- **Adjust iterations** (`AGENT_MAX_ITERATIONS`) to balance quality vs speed
- **Monitor costs** - agent makes multiple API calls

---

## Troubleshooting

### Agent not running?

Check:
1. `USE_AGENT=true` in environment
2. `langchain-google-genai` installed: `pip install langchain-google-genai`
3. `GEMINI_API_KEY` configured

### Agent iterations exceeded?

Increase `AGENT_MAX_ITERATIONS`:
```bash
export AGENT_MAX_ITERATIONS=20
```

### Want to see agent thinking?

Enable verbose mode:
```bash
export AGENT_VERBOSE=true
```

Check logs for agent reasoning steps.

---

## Future Enhancements

Potential improvements:

1. **RAG Integration** - Query Pinecone knowledge base from agent tools
2. **CVE Database Tool** - Live lookup of CVE details from NVD
3. **Exploit Check Tool** - Check if exploits exist for CVEs
4. **Risk Trend Tool** - Compare current vs historical risk scores
5. **Compliance Tool** - Map findings to NIST/ISO frameworks
6. **Custom Tools** - Client-specific analysis tools
7. **Multi-Agent** - Separate agents for different analysis types

---

## References

- [LangChain Agents Documentation](https://python.langchain.com/docs/modules/agents/)
- [ReAct Pattern Paper](https://arxiv.org/abs/2210.03629)
- [Google Gemini API](https://ai.google.dev/docs)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

