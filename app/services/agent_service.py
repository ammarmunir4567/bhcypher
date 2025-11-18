from __future__ import annotations

import json
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import Tool
from langchain_core.prompts import PromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI
import google.generativeai as genai

from app.core.config import settings

logger = logging.getLogger(__name__)

PROMPTS_DIR = Path(__file__).parent.parent / "prompts"

# Initialize Gemini for tool use
genai.configure(api_key=settings.gemini_api_key)


# ==================== AGENT TOOLS ====================

def analyze_vulnerabilities_tool(vulnerabilities_data: str) -> str:
    """
    Tool: Analyze vulnerabilities from scan data and categorize by severity.
    
    Args:
        vulnerabilities_data: JSON string or summary text containing vulnerability data
    
    Returns:
        Analysis summary with severity breakdown
    """
    try:
        # Try to parse as JSON first
        try:
            if isinstance(vulnerabilities_data, str):
                # Handle both JSON string and already-parsed data
                if vulnerabilities_data.strip().startswith('[') or vulnerabilities_data.strip().startswith('{'):
                    vulns = json.loads(vulnerabilities_data)
                else:
                    # If it's not JSON, return error
                    return json.dumps({
                        "error": "Input must be valid JSON array of vulnerabilities",
                        "received_type": "non-JSON string"
                    })
            else:
                vulns = vulnerabilities_data
        except json.JSONDecodeError as je:
            logger.error(f"JSON decode error: {je}")
            return json.dumps({
                "error": f"Invalid JSON format: {str(je)}",
                "hint": "Ensure vulnerability descriptions are properly escaped"
            })
        
        # Ensure vulns is a list
        if not isinstance(vulns, list):
            if isinstance(vulns, dict) and 'vulnerabilities' in vulns:
                vulns = vulns['vulnerabilities']
            else:
                return json.dumps({"error": "Expected array of vulnerabilities"})
        
        # Categorize by severity patterns in CVE descriptions
        critical = []
        high = []
        medium = []
        low = []
        
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
                
            cve_id = vuln.get("cve_id", "UNKNOWN")
            description = vuln.get("description", "").lower()
            
            # Severity heuristics based on keywords
            if any(kw in description for kw in ["remote code execution", "rce", "critical", "arbitrary code", "execute arbitrary code"]):
                critical.append(cve_id)
            elif any(kw in description for kw in ["buffer overflow", "stack-based", "heap-based"]):
                critical.append(cve_id)
            elif any(kw in description for kw in ["high", "denial of service", "dos", "authentication bypass", "sql injection", "privilege escalation"]):
                high.append(cve_id)
            elif any(kw in description for kw in ["medium", "information disclosure", "cross-site scripting", "xss"]):
                medium.append(cve_id)
            else:
                low.append(cve_id)
        
        analysis = {
            "total": len(vulns),
            "critical": {"count": len(critical), "cves": critical},
            "high": {"count": len(high), "cves": high},
            "medium": {"count": len(medium), "cves": medium},
            "low": {"count": len(low), "cves": low}
        }
        
        return json.dumps(analysis, indent=2)
    
    except Exception as e:
        logger.error(f"Error in analyze_vulnerabilities_tool: {e}", exc_info=True)
        return json.dumps({"error": str(e), "type": type(e).__name__})


def count_vulnerabilities_by_severity_tool(vulnerability_list: str) -> str:
    """
    Tool: Quick vulnerability counter - just provide CVE IDs separated by commas.
    
    Args:
        vulnerability_list: Comma-separated list of CVE IDs or count summary like "10 vulnerabilities"
    
    Returns:
        Quick severity estimate
    """
    try:
        # Simple heuristic-based counting
        if "," in vulnerability_list:
            cve_ids = [c.strip() for c in vulnerability_list.split(",")]
            total = len(cve_ids)
        else:
            # Try to extract number
            import re
            numbers = re.findall(r'\d+', vulnerability_list)
            total = int(numbers[0]) if numbers else 0
        
        # Rough estimate (can be refined by analyze_vulnerabilities later)
        result = {
            "total": total,
            "estimated_severity": "High" if total > 5 else "Medium" if total > 2 else "Low",
            "note": "This is a quick estimate. Use analyze_vulnerabilities for detailed breakdown."
        }
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


def calculate_risk_score_tool(severity_breakdown: str) -> str:
    """
    Tool: Calculate overall risk score based on severity breakdown.
    
    Args:
        severity_breakdown: JSON string with severity counts
    
    Returns:
        Risk score (0-10) and risk level
    """
    try:
        breakdown = json.loads(severity_breakdown)
        
        # Weighted risk calculation
        critical_weight = 10.0
        high_weight = 7.0
        medium_weight = 4.0
        low_weight = 1.0
        
        # Handle both formats: {"critical": {"count": 2}} or {"critical": 2}
        def get_count(severity_key):
            value = breakdown.get(severity_key, 0)
            if isinstance(value, dict):
                return value.get("count", 0)
            elif isinstance(value, (int, float)):
                return int(value)
            return 0
        
        critical_count = get_count("critical")
        high_count = get_count("high")
        medium_count = get_count("medium")
        low_count = get_count("low")
        total = breakdown.get("total", critical_count + high_count + medium_count + low_count)
        
        # Calculate weighted score
        weighted_sum = (
            critical_count * critical_weight +
            high_count * high_weight +
            medium_count * medium_weight +
            low_count * low_weight
        )
        
        # Normalize to 0-10 scale
        risk_score = min(10.0, (weighted_sum / max(total, 1)) * 1.5)
        
        # Determine risk level
        if risk_score >= 8.0:
            risk_level = "Critical"
        elif risk_score >= 6.0:
            risk_level = "High"
        elif risk_score >= 4.0:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        result = {
            "risk_score": round(risk_score, 2),
            "risk_level": risk_level,
            "details": {
                "critical_vulns": critical_count,
                "high_vulns": high_count,
                "medium_vulns": medium_count,
                "low_vulns": low_count,
                "total_vulns": total
            }
        }
        
        return json.dumps(result, indent=2)
    
    except json.JSONDecodeError as je:
        logger.error(f"JSON decode error in calculate_risk_score_tool: {je}")
        return json.dumps({
            "error": f"Invalid JSON format: {str(je)}",
            "hint": "Provide severity counts as JSON: {'critical': 2, 'high': 3, 'medium': 0, 'low': 5}"
        })
    except Exception as e:
        logger.error(f"Error in calculate_risk_score_tool: {e}", exc_info=True)
        return json.dumps({"error": str(e), "type": type(e).__name__})


def generate_remediation_tool(cve_data: str) -> str:
    """
    Tool: Generate remediation recommendations for a CVE using AI.
    
    Args:
        cve_data: JSON string with CVE ID and description
    
    Returns:
        AI-generated remediation recommendations with priority and steps
    """
    try:
        data = json.loads(cve_data)
        cve_id = data.get("cve_id", "UNKNOWN")
        description = data.get("description", "")
        severity = data.get("severity", "medium").lower()
        
        # Use AI to generate contextual remediation recommendations
        prompt = f"""As a cybersecurity expert, provide specific remediation recommendations for this vulnerability:

CVE ID: {cve_id}
Severity: {severity}
Description: {description}

Generate actionable remediation steps following industry best practices (NIST, OWASP, CIS).
Include:
1. Immediate actions
2. Short-term mitigations
3. Long-term fixes
4. Monitoring recommendations

Format as a JSON object with these fields:
- recommendations: array of specific actionable steps
- timeline: recommended timeline for remediation
- references: relevant security frameworks/standards

Return ONLY valid JSON, no additional text."""

        model = genai.GenerativeModel(settings.gemini_model)
        response = model.generate_content(prompt)
        ai_output = response.text.strip()
        
        # Parse AI response
        try:
            # Extract JSON from response
            if "```json" in ai_output:
                ai_output = ai_output.split("```json")[1].split("```")[0].strip()
            elif "```" in ai_output:
                ai_output = ai_output.split("```")[1].split("```")[0].strip()
            
            # Try to find JSON object
            start = ai_output.find("{")
            end = ai_output.rfind("}") + 1
            if start >= 0 and end > start:
                ai_output = ai_output[start:end]
            
            ai_recommendations = json.loads(ai_output)
        except json.JSONDecodeError:
            # Fallback: use raw text as recommendations
            ai_recommendations = {
                "recommendations": [line.strip() for line in ai_output.split("\n") if line.strip() and not line.strip().startswith("#")],
                "timeline": _get_priority_timeline(severity),
                "references": []
            }
        
        # Set priority based on severity
        priority = _get_priority_timeline(severity)
        
        result = {
            "cve_id": cve_id,
            "priority": priority,
            "recommendations": ai_recommendations.get("recommendations", []),
            "timeline": ai_recommendations.get("timeline", priority),
            "references": [
                f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "NIST SP 800-53: Security Controls",
                "OWASP Top 10",
                "MITRE ATT&CK Framework"
            ] + ai_recommendations.get("references", [])
        }
        
        return json.dumps(result, indent=2)
    
    except Exception as e:
        logger.error(f"Error in generate_remediation_tool: {e}")
        return json.dumps({
            "error": str(e),
            "cve_id": data.get("cve_id", "UNKNOWN") if 'data' in locals() else "UNKNOWN"
        })


def _get_priority_timeline(severity: str) -> str:
    """Get remediation priority timeline based on severity."""
    severity = severity.lower()
    if severity in ["critical", "high"]:
        return "Immediate (24-48 hours)"
    elif severity == "medium":
        return "High (1 week)"
    else:
        return "Medium (2-4 weeks)"


def get_security_context_tool(query: str) -> str:
    """
    Tool: Retrieve security context and best practices using AI and optional vector store.
    
    Args:
        query: Security-related query
    
    Returns:
        AI-generated relevant security context and guidelines
    """
    try:
        # Try to query vector store knowledge base first
        try:
            from app.services.vector_store_service import get_vector_store_service
            
            vector_store = get_vector_store_service()
            kb_results = vector_store.query_knowledge_base(
                query_text=query,
                top_k=3
            )
            
            # Extract relevant context from vector store
            context_from_kb = []
            for match in kb_results:
                metadata = match.get("metadata", {})
                text = metadata.get("text", "")
                if text:
                    context_from_kb.append(text)
            
            if context_from_kb:
                logger.info(f"Retrieved {len(context_from_kb)} contexts from vector store")
                kb_context = "\n\n".join(context_from_kb)
            else:
                kb_context = ""
        except Exception as e:
            logger.warning(f"Could not query vector store: {e}")
            kb_context = ""
        
        # Use AI to generate contextual security guidance
        kb_section = f"Relevant knowledge base context:\n{kb_context}\n" if kb_context else ""
        
        prompt = f"""As a cybersecurity expert, provide comprehensive guidance on the following security topic:

Query: {query}

{kb_section}
Provide:
1. Industry best practices (NIST, OWASP, CIS, ISO 27001)
2. Step-by-step implementation guidance
3. Common pitfalls to avoid
4. Relevant security frameworks and standards

Be specific, actionable, and reference established security frameworks."""

        model = genai.GenerativeModel(settings.gemini_model)
        response = model.generate_content(prompt)
        context = response.text.strip()
        
        return context
    
    except Exception as e:
        logger.error(f"Error in get_security_context_tool: {e}")
        # Minimal fallback - just return the error context
        return f"Error retrieving security context: {str(e)}. Please consult NIST, OWASP, or CIS security frameworks for guidance on: {query}"


# ==================== LANGCHAIN AGENT SETUP ====================

def create_security_agent() -> AgentExecutor:
    """
    Create a LangChain ReAct agent with security analysis tools.
    
    Returns:
        AgentExecutor configured with security tools
    """
    # Initialize Gemini LLM
    llm = ChatGoogleGenerativeAI(
        model=settings.gemini_model,
        google_api_key=settings.gemini_api_key,
        temperature=0.2,  # Lower temperature for more consistent security analysis
        convert_system_message_to_human=True
    )
    
    # Define tools for the agent
    tools = [
        Tool(
            name="count_vulnerabilities",
            func=count_vulnerabilities_by_severity_tool,
            description="""
            Quick vulnerability counter for simple cases.
            Input: Just the number of vulnerabilities (e.g., "10") or comma-separated CVE IDs (e.g., "CVE-2024-1,CVE-2024-2,CVE-2024-3")
            Returns quick severity estimate. Use this first if you're having trouble with JSON formatting.
            """
        ),
        Tool(
            name="analyze_vulnerabilities",
            func=analyze_vulnerabilities_tool,
            description="""
            Detailed vulnerability analysis - categorizes by severity (Critical, High, Medium, Low).
            Input: Use the SIMPLIFIED vulnerability data provided in the question. Copy it exactly as provided.
            The input should be a JSON array: [{"cve_id":"CVE-XXXX","description":"brief"}]
            If you get JSON parsing errors, use count_vulnerabilities tool instead.
            Returns severity breakdown with CVE IDs in each category.
            """
        ),
        Tool(
            name="calculate_risk_score",
            func=calculate_risk_score_tool,
            description="""
            Calculates overall risk score (0-10) based on severity breakdown.
            Input: JSON with severity counts. Accepts two formats:
            1. Simple: {"critical": 2, "high": 3, "medium": 0, "low": 5}
            2. Detailed: {"critical": {"count": 2}, "high": {"count": 3}, "medium": {"count": 0}, "low": {"count": 5}}
            Returns risk score (0-10), risk level (Critical/High/Medium/Low), and detailed breakdown.
            """
        ),
        Tool(
            name="generate_remediation",
            func=generate_remediation_tool,
            description="""
            Generates remediation recommendations for a specific CVE.
            Input should be a JSON string with 'cve_id', 'description', and 'severity' fields.
            Returns prioritized recommendations with actionable steps and references.
            """
        ),
        Tool(
            name="get_security_context",
            func=get_security_context_tool,
            description="""
            Retrieves security best practices and context for different security domains.
            Input should be a query string about security topics (patch management, incident response, etc.).
            Returns relevant security guidelines and frameworks.
            """
        )
    ]
    
    # Create ReAct agent prompt
    agent_prompt = PromptTemplate.from_template("""
You are a senior cybersecurity analyst AI agent. Your task is to analyze security scan data and generate a comprehensive security assessment report.

You have access to the following tools:
{tools}

Tool Names: {tool_names}

Use the following format:

Question: the input question you must answer
Thought: you should always think about what to do
Action: the action to take, should be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: the final answer to the original input question

Your analysis workflow:
1. Start with count_vulnerabilities using just the CVE IDs or total count to get a quick estimate
2. If you can format the SIMPLIFIED vulnerability data correctly, use analyze_vulnerabilities for detailed breakdown
   - ONLY use the simplified data provided, copy it exactly as shown
   - If you get JSON errors, skip this step and use the count from step 1
3. Use calculate_risk_score with the severity breakdown from step 1 or 2
4. For critical/high CVEs, use generate_remediation (one CVE at a time with simple JSON)
5. Use get_security_context if you need best practices guidance  
6. Compile everything into your final comprehensive JSON report

CRITICAL: If any tool returns an error, continue with the analysis using the information you have. Don't retry the same failing tool multiple times.

The final report MUST be valid JSON with this exact structure:
{{
  "executive_summary": "Overall risk assessment with key findings",
  "system_overview": "Host details and system configuration",
  "findings": [
    {{
      "cve_id": "CVE-XXXX-XXXX",
      "title": "Vulnerability title",
      "severity": "Critical|High|Medium|Low",
      "description": "Detailed description",
      "impact": "Impact assessment",
      "recommendation": "Actionable remediation steps",
      "references": ["NIST", "OWASP", "MITRE ATT&CK"]
    }}
  ],
  "recommendations": "Prioritized remediation plan",
  "risk_score": 7.5,
  "risk_level": "High"
}}

Begin!

Question: {input}
Thought: {agent_scratchpad}
""")
    
    # Create ReAct agent
    agent = create_react_agent(
        llm=llm,
        tools=tools,
        prompt=agent_prompt
    )
    
    # Create agent executor with robust error handling
    agent_executor = AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=settings.agent_verbose,
        max_iterations=min(settings.agent_max_iterations, 20),  # Cap at 20 to avoid infinite loops
        handle_parsing_errors="Check your output and make sure it conforms to the specified format!",
        return_intermediate_steps=True,
        max_execution_time=300  # 5 minute timeout
    )
    
    logger.info("Security analysis agent created successfully")
    return agent_executor


# ==================== AGENT REPORT GENERATION ====================

def _prepare_simplified_vulns(findings: List[Dict]) -> str:
    """Prepare simplified vulnerability data to avoid JSON parsing issues."""
    simplified = []
    for vuln in findings:
        # Truncate and clean description
        desc = vuln.get("description", "")[:200]
        # Remove problematic characters
        desc = desc.replace('"', "'").replace('\n', ' ').replace('\r', ' ')
        simplified.append({
            "cve_id": vuln.get("cve_id", "UNKNOWN"),
            "description": desc
        })
    return json.dumps(simplified)


def generate_report_with_agent(parsed_scan: Dict) -> Dict:
    """
    Generate security report using multi-agent orchestration system.
    
    This function now uses a hierarchical multi-agent architecture instead of
    a single agent. The multi-agent system distributes work across specialized
    agents for better performance, reliability, and parallel processing.
    
    Args:
        parsed_scan: Parsed scan data with host info and vulnerabilities
    
    Returns:
        Comprehensive security report dictionary
    """
    try:
        # Check if multi-agent system should be used
        use_multi_agent = settings.use_agent  # Reuse the existing agent flag
        
        if use_multi_agent:
            logger.info("🎯 Using multi-agent orchestration system")
            from app.services.multi_agent_service import SecurityReportOrchestrator
            
            orchestrator = SecurityReportOrchestrator()
            report_data = orchestrator.generate_report(parsed_scan)
            
            logger.info("✅ Multi-agent report generation successful")
            return report_data
        else:
            # Fall back to single agent if multi-agent is disabled
            logger.info("Using single agent system (legacy mode)")
            return _generate_with_single_agent(parsed_scan)
    
    except Exception as e:
        logger.error(f"Error in multi-agent report generation: {e}", exc_info=True)
        logger.info("Falling back to single agent system")
        try:
            return _generate_with_single_agent(parsed_scan)
        except Exception as e2:
            logger.error(f"Single agent also failed: {e2}", exc_info=True)
            return _generate_stub_report(parsed_scan)


def _generate_with_single_agent(parsed_scan: Dict) -> Dict:
    """
    Legacy single-agent report generation (kept as fallback).
    
    Args:
        parsed_scan: Parsed scan data
        
    Returns:
        Report dictionary
    """
    try:
        logger.info("Creating security analysis agent (single agent mode)...")
        agent = create_security_agent()
        
        # Prepare input for agent
        host_info = parsed_scan.get("host", {})
        findings = parsed_scan.get("findings", [])
        summary = parsed_scan.get("summary", {})
        
        # Prepare simplified vulnerability data for tools
        simplified_vulns = _prepare_simplified_vulns(findings)
        
        # Construct agent input
        agent_input = f"""
Analyze this security scan and generate a comprehensive security assessment report.

SYSTEM INFORMATION:
- Hostname: {host_info.get('hostname', 'Unknown')}
- OS: {host_info.get('os', 'Unknown')} {host_info.get('os_version', '')}
- Total Vulnerabilities: {len(findings)}

VULNERABILITIES DATA (Simplified for tools):
{simplified_vulns}

FULL VULNERABILITY DETAILS:
{json.dumps([{"cve_id": v.get("cve_id"), "description": v.get("description")[:300]} for v in findings], indent=2)}

SCAN SUMMARY:
{json.dumps(summary, indent=2)}

Generate a complete security assessment report with executive summary, detailed findings for each CVE, 
and prioritized recommendations. Use your tools to analyze severity, calculate risk, and generate 
specific remediation steps. Use the SIMPLIFIED data when calling tools to avoid JSON parsing errors.
"""
        
        logger.info(f"Running agent with {len(findings)} vulnerabilities...")
        
        # Execute agent
        result = agent.invoke({"input": agent_input})
        
        # Extract output
        agent_output = result.get("output", "")
        
        logger.info(f"Agent execution completed. Output length: {len(agent_output)} chars")
        
        # Parse agent output as JSON
        report_data = _extract_json_from_agent_output(agent_output)
        
        if report_data:
            logger.info("Successfully parsed JSON from agent output")
            # Add severity breakdown if not present
            if "severity_breakdown" not in report_data:
                report_data["severity_breakdown"] = _calculate_severity_breakdown(report_data.get("findings", []))
            return report_data
        else:
            logger.warning("Could not parse JSON from agent, generating fallback report")
            return _generate_fallback_report(parsed_scan, agent_output)
    
    except Exception as e:
        logger.error(f"Error in single agent report generation: {e}", exc_info=True)
        return _generate_stub_report(parsed_scan)


def _extract_json_from_agent_output(text: str) -> Optional[Dict]:
    """Extract JSON from agent output, handling various formats."""
    if not text:
        return None
    
    # Try to find JSON in markdown code blocks
    if "```json" in text:
        try:
            json_text = text.split("```json")[1].split("```")[0].strip()
            return json.loads(json_text)
        except (IndexError, json.JSONDecodeError):
            pass
    
    # Try to find JSON in regular code blocks
    if "```" in text:
        try:
            parts = text.split("```")
            for part in parts:
                part = part.strip()
                if part.startswith("{") and part.endswith("}"):
                    return json.loads(part)
        except json.JSONDecodeError:
            pass
    
    # Try to find raw JSON
    try:
        # Find first { and last }
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            json_text = text[start:end]
            return json.loads(json_text)
    except json.JSONDecodeError:
        pass
    
    return None


def _generate_fallback_report(parsed_scan: Dict, agent_text: str) -> Dict:
    """Generate report from agent text output when JSON parsing fails, using AI to structure it."""
    host = parsed_scan.get("host", {})
    findings = parsed_scan.get("findings", [])
    summary = parsed_scan.get("summary", {})
    
    try:
        # Use AI to structure the agent's text output into proper report format
        prompt = f"""Convert this security analysis into a structured JSON report:

Host: {host.get('hostname', 'Unknown')}
OS: {host.get('os', 'Unknown')} {host.get('os_version', '')}
Total Vulnerabilities: {len(findings)}

Agent Analysis Output:
{agent_text}

Vulnerability Data:
{json.dumps(findings[:5], indent=2)}  # Include first 5 for context

Generate a comprehensive security report in this JSON structure:
{{
  "executive_summary": "2-3 sentence overall assessment",
  "system_overview": "Host details and configuration",
  "findings": [
    {{
      "cve_id": "CVE-ID",
      "title": "Vulnerability title",
      "severity": "Critical|High|Medium|Low",
      "description": "Description",
      "impact": "Impact assessment",
      "recommendation": "Specific remediation steps",
      "references": ["Framework references"]
    }}
  ],
  "recommendations": "Prioritized action plan",
  "risk_score": {summary.get('risk_score', 7.0)},
  "risk_level": "Critical|High|Medium|Low"
}}

Return ONLY valid JSON."""

        model = genai.GenerativeModel(settings.gemini_model)
        response = model.generate_content(prompt)
        ai_output = response.text.strip()
        
        # Extract JSON
        if "```json" in ai_output:
            ai_output = ai_output.split("```json")[1].split("```")[0].strip()
        elif "```" in ai_output:
            ai_output = ai_output.split("```")[1].split("```")[0].strip()
        
        start = ai_output.find("{")
        end = ai_output.rfind("}") + 1
        if start >= 0 and end > start:
            ai_output = ai_output[start:end]
        
        report_data = json.loads(ai_output)
        
        # Add severity breakdown
        report_data["severity_breakdown"] = _calculate_severity_breakdown(report_data.get("findings", []))
        
        return report_data
    
    except Exception as e:
        logger.error(f"AI fallback report generation failed: {e}")
        # Last resort: minimal structured output
        risk_score = summary.get("risk_score", 7.0)
        risk_level = _determine_risk_level(risk_score)
        
        converted_findings = _convert_findings_to_report_format(findings[:10])
        
        return {
            "executive_summary": agent_text[:500] if agent_text else f"Security assessment for {host.get('hostname', 'system')} identified {len(findings)} vulnerabilities requiring attention.",
            "system_overview": f"Host: {host.get('hostname', 'Unknown')}, OS: {host.get('os', 'Unknown')} {host.get('os_version', '')}",
            "findings": converted_findings,
            "recommendations": agent_text[-500:] if len(agent_text) > 500 else "Review and remediate identified vulnerabilities based on risk prioritization.",
            "risk_score": risk_score,
            "risk_level": risk_level,
            "severity_breakdown": _calculate_severity_breakdown(converted_findings)
        }


def _generate_stub_report(parsed_scan: Dict) -> Dict:
    """Generate stub report when agent fails, using simple AI generation if possible."""
    host = parsed_scan.get("host", {})
    findings = parsed_scan.get("findings", [])
    summary = parsed_scan.get("summary", {})
    
    hostname = host.get("hostname", "Unknown")
    findings_count = len(findings)
    risk_score = summary.get("risk_score", 7.0)
    risk_level = _determine_risk_level(risk_score)
    
    try:
        # Try simple AI generation for stub report
        prompt = f"""Generate a brief security report for:
Host: {hostname}
OS: {host.get('os', 'Unknown')}
Vulnerabilities found: {findings_count}
Risk Score: {risk_score}

Top 3 CVEs:
{json.dumps(findings[:3], indent=2)}

Provide:
1. Executive summary (2 sentences)
2. Top recommendations (3 bullet points)

Format as JSON:
{{
  "executive_summary": "...",
  "recommendations": "..."
}}"""

        model = genai.GenerativeModel(settings.gemini_model)
        response = model.generate_content(prompt)
        ai_text = response.text.strip()
        
        # Extract JSON
        if "```json" in ai_text:
            ai_text = ai_text.split("```json")[1].split("```")[0].strip()
        start = ai_text.find("{")
        end = ai_text.rfind("}") + 1
        if start >= 0 and end > start:
            ai_data = json.loads(ai_text[start:end])
            executive_summary = ai_data.get("executive_summary", f"Security scan for {hostname} identified {findings_count} vulnerabilities.")
            recommendations = ai_data.get("recommendations", "Review and remediate vulnerabilities promptly.")
        else:
            raise ValueError("Could not extract JSON")
    
    except Exception as e:
        logger.warning(f"AI stub report failed: {e}")
        executive_summary = f"Security scan for {hostname} identified {findings_count} vulnerabilities requiring attention."
        recommendations = "Prioritize vulnerabilities by severity and apply security patches promptly following vendor guidelines."
    
    converted_findings = _convert_findings_to_report_format(findings[:10])
    
    return {
        "executive_summary": executive_summary,
        "system_overview": f"Hostname: {hostname}, OS: {host.get('os', 'Unknown')} {host.get('os_version', '')}",
        "findings": converted_findings,
        "recommendations": recommendations,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "severity_breakdown": _calculate_severity_breakdown(converted_findings)
    }


def _calculate_severity_breakdown(findings: List[Dict]) -> Dict:
    """Calculate severity breakdown from findings list."""
    breakdown = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }
    
    for finding in findings:
        severity = finding.get("severity", "").lower()
        if severity in breakdown:
            breakdown[severity] += 1
        elif severity == "informational":
            breakdown["info"] += 1
    
    return breakdown


def _determine_risk_level(risk_score: float) -> str:
    """Determine risk level from risk score."""
    if risk_score >= 8.0:
        return "Critical"
    elif risk_score >= 6.0:
        return "High"
    elif risk_score >= 4.0:
        return "Medium"
    else:
        return "Low"


def _convert_findings_to_report_format(findings: List[Dict]) -> List[Dict]:
    """Convert raw findings to report format with minimal processing."""
    report_findings = []
    for finding in findings:
        cve_id = finding.get("cve_id", "UNKNOWN")
        description = finding.get("description", "No description available")
        
        # Basic severity determination from description keywords
        desc_lower = description.lower()
        if any(kw in desc_lower for kw in ["critical", "remote code execution", "rce"]):
            severity = "Critical"
        elif any(kw in desc_lower for kw in ["high", "sql injection", "authentication bypass"]):
            severity = "High"
        elif any(kw in desc_lower for kw in ["medium", "xss", "cross-site"]):
            severity = "Medium"
        else:
            severity = "Low"
        
        report_findings.append({
            "cve_id": cve_id,
            "title": f"Vulnerability: {cve_id}",
            "severity": severity,
            "description": description[:300] if len(description) > 300 else description,
            "impact": f"{severity} severity vulnerability requiring attention",
            "recommendation": f"Review {cve_id} details and apply vendor-recommended patches",
            "references": [f"https://nvd.nist.gov/vuln/detail/{cve_id}", "NIST", "OWASP"]
        })
    
    return report_findings

