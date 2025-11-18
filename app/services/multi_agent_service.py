"""
Multi-Agent Security Report Generation System

This module implements a hierarchical multi-agent architecture for generating
security assessment reports. Instead of a single agent handling all tasks,
this system distributes work across specialized agents:

1. Orchestrator Agent - Coordinates the entire workflow
2. Severity Analysis Agent - Categorizes vulnerabilities by severity
3. Risk Scoring Agent - Calculates overall risk metrics
4. Remediation Agent Pool - Parallel workers for generating remediation (one per CVE)
5. Report Builder Agent - Assembles final report from all outputs

This approach reduces context overload, enables parallel processing,
and improves reliability through focused, specialized agents.
"""

from __future__ import annotations

import json
import logging
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from langchain_google_genai import ChatGoogleGenerativeAI
import google.generativeai as genai

from app.core.config import settings

logger = logging.getLogger(__name__)

# Configure Gemini
genai.configure(api_key=settings.gemini_api_key)


# ==================== UTILITY FUNCTIONS ====================

def _extract_json_from_text(text: str) -> Optional[Dict]:
    """Extract JSON from text that might contain markdown or other formatting."""
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
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            json_text = text[start:end]
            return json.loads(json_text)
    except json.JSONDecodeError:
        pass
    
    return None


def _get_cve_description(cve_id: str, findings: List[Dict]) -> str:
    """Get description for a specific CVE from findings list."""
    for finding in findings:
        if finding.get("cve_id") == cve_id:
            return finding.get("description", "No description available")
    return "No description available"


# ==================== SPECIALIZED AGENTS ====================

class SeverityAnalysisAgent:
    """
    Specialized agent for vulnerability severity analysis only.
    Single responsibility: categorize vulnerabilities by severity.
    
    This agent analyzes all vulnerabilities quickly without generating
    detailed remediation, keeping context focused and execution fast.
    """
    
    def __init__(self):
        self.llm = ChatGoogleGenerativeAI(
            model=settings.gemini_model,
            google_api_key=settings.gemini_api_key,
            temperature=0.1,  # Low temperature for consistent categorization
            convert_system_message_to_human=True
        )
    
    def analyze(self, parsed_scan: Dict) -> Dict:
        """
        Analyze all vulnerabilities and categorize by severity.
        Returns structured breakdown without remediation details.
        
        Args:
            parsed_scan: Parsed scan data with findings
            
        Returns:
            Dict with severity breakdown and CVE lists
        """
        findings = parsed_scan.get("findings", [])
        
        if not findings:
            return {"total": 0, "critical": {"count": 0, "cves": []}, 
                    "high": {"count": 0, "cves": []}, "medium": {"count": 0, "cves": []}, 
                    "low": {"count": 0, "cves": []}}
        
        logger.info(f"📊 Analyzing {len(findings)} vulnerabilities for severity")
        
        # Create focused prompt for severity analysis only
        vulns_summary = [
            {
                "cve_id": f.get("cve_id", "UNKNOWN"),
                "description": f.get("description", "")[:200]
            }
            for f in findings
        ]
        
        prompt = f"""Analyze these {len(findings)} vulnerabilities and categorize by severity.

Vulnerabilities:
{json.dumps(vulns_summary, indent=2)}

Return ONLY this JSON structure (no other text):
{{
  "total": {len(findings)},
  "critical": {{"count": 0, "cves": []}},
  "high": {{"count": 0, "cves": []}},
  "medium": {{"count": 0, "cves": []}},
  "low": {{"count": 0, "cves": []}}
}}

Categorize based on impact:
- Critical: Remote code execution, privilege escalation, complete system compromise
- High: Data exposure, authentication bypass, SQL injection
- Medium: XSS, CSRF, information disclosure, denial of service
- Low: Minor issues, deprecated features, low-impact vulnerabilities"""
        
        try:
            response = self.llm.invoke(prompt)
            result = _extract_json_from_text(response.content)
            
            if result:
                logger.info(f"✅ Severity analysis: {result.get('critical', {}).get('count', 0)} critical, "
                           f"{result.get('high', {}).get('count', 0)} high, "
                           f"{result.get('medium', {}).get('count', 0)} medium, "
                           f"{result.get('low', {}).get('count', 0)} low")
                return result
            else:
                logger.warning("Could not parse severity analysis, using fallback")
                return self._fallback_analysis(findings)
                
        except Exception as e:
            logger.error(f"❌ Severity analysis failed: {e}")
            return self._fallback_analysis(findings)
    
    def _fallback_analysis(self, findings: List[Dict]) -> Dict:
        """Simple keyword-based fallback when AI analysis fails."""
        result = {
            "total": len(findings),
            "critical": {"count": 0, "cves": []},
            "high": {"count": 0, "cves": []},
            "medium": {"count": 0, "cves": []},
            "low": {"count": 0, "cves": []}
        }
        
        for finding in findings:
            cve_id = finding.get("cve_id", "UNKNOWN")
            desc = finding.get("description", "").lower()
            
            if any(kw in desc for kw in ["remote code execution", "rce", "privilege escalation", "buffer overflow"]):
                result["critical"]["count"] += 1
                result["critical"]["cves"].append(cve_id)
            elif any(kw in desc for kw in ["sql injection", "authentication bypass", "data exposure"]):
                result["high"]["count"] += 1
                result["high"]["cves"].append(cve_id)
            elif any(kw in desc for kw in ["xss", "csrf", "denial of service", "information disclosure"]):
                result["medium"]["count"] += 1
                result["medium"]["cves"].append(cve_id)
            else:
                result["low"]["count"] += 1
                result["low"]["cves"].append(cve_id)
        
        return result


class RiskScoringAgent:
    """
    Specialized agent for calculating risk scores.
    Uses weighted severity counts to generate overall risk metrics.
    """
    
    def calculate_risk(self, analysis_result: Dict) -> Dict:
        """
        Calculate overall risk score and level from severity analysis.
        
        Args:
            analysis_result: Output from SeverityAnalysisAgent
            
        Returns:
            Dict with risk_score, risk_level, and details
        """
        logger.info("📈 Calculating risk scores")
        
        critical_count = analysis_result.get("critical", {}).get("count", 0)
        high_count = analysis_result.get("high", {}).get("count", 0)
        medium_count = analysis_result.get("medium", {}).get("count", 0)
        low_count = analysis_result.get("low", {}).get("count", 0)
        total = analysis_result.get("total", 0)
        
        # Weighted risk calculation
        critical_weight = 10.0
        high_weight = 7.0
        medium_weight = 4.0
        low_weight = 1.0
        
        weighted_sum = (
            critical_count * critical_weight +
            high_count * high_weight +
            medium_count * medium_weight +
            low_count * low_weight
        )
        
        # Normalize to 0-10 scale
        risk_score = min(10.0, (weighted_sum / max(total, 1)) * 1.5) if total > 0 else 0.0
        
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
        
        logger.info(f"✅ Risk: {result['risk_score']}/10.0 ({result['risk_level']})")
        return result


class RemediationWorkerAgent:
    """
    Individual worker agent for generating remediation for ONE CVE.
    Lightweight, focused on single task, designed for parallel execution.
    """
    
    def __init__(self):
        self.model = genai.GenerativeModel(settings.gemini_model)
    
    def generate_remediation(self, cve: Dict) -> Dict:
        """
        Generate detailed remediation for a single CVE.
        
        Args:
            cve: Dict with cve_id, severity, description
            
        Returns:
            Dict with remediation details
        """
        cve_id = cve.get("cve_id", "UNKNOWN")
        severity = cve.get("severity", "Unknown")
        description = cve.get("description", "")[:500]
        
        logger.info(f"🔧 Generating remediation for {cve_id} ({severity})")
        
        # Focused prompt for single CVE remediation
        prompt = f"""Generate actionable remediation recommendations for this vulnerability:

CVE ID: {cve_id}
Severity: {severity}
Description: {description}

Provide ONLY valid JSON with this structure:
{{
  "cve_id": "{cve_id}",
  "severity": "{severity}",
  "priority": "Immediate (24-48 hours)|Short-term (1-2 weeks)|Long-term (1-3 months)",
  "steps": [
    "Specific action step 1",
    "Specific action step 2",
    "Specific action step 3"
  ],
  "references": ["NIST SP 800-53", "OWASP", "CIS Controls"]
}}

Focus on:
1. Immediate actionable steps (not theory)
2. Specific patch/upgrade instructions
3. Workarounds if patch unavailable
4. Monitoring recommendations"""
        
        try:
            response = self.model.generate_content(prompt)
            result = _extract_json_from_text(response.text)
            
            if result and result.get("cve_id"):
                logger.info(f"✅ Remediation complete for {cve_id}")
                return result
            else:
                logger.warning(f"Could not parse remediation for {cve_id}, using stub")
                return self._stub_remediation(cve_id, severity)
                
        except Exception as e:
            logger.error(f"❌ Remediation generation failed for {cve_id}: {e}")
            return self._stub_remediation(cve_id, severity)
    
    def _stub_remediation(self, cve_id: str, severity: str) -> Dict:
        """Generate basic stub remediation when AI fails."""
        return {
            "cve_id": cve_id,
            "severity": severity,
            "priority": "Immediate (24-48 hours)" if severity in ["Critical", "High"] else "Short-term (1-2 weeks)",
            "steps": [
                f"Review {cve_id} details at https://nvd.nist.gov/vuln/detail/{cve_id}",
                "Check vendor security advisories for patches",
                "Apply security updates following change management procedures",
                "Verify remediation through vulnerability scanning"
            ],
            "references": ["NVD", "vendor security advisory", "NIST SP 800-53"]
        }


class RemediationAgentPool:
    """
    Pool of remediation agents that process CVEs in parallel.
    Each worker handles one CVE at a time, enabling concurrent processing.
    """
    
    def __init__(self, max_workers: int = 3):
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
    
    def process_parallel(self, cves: List[Dict], max_concurrent: int = 3) -> List[Dict]:
        """
        Process multiple CVEs in parallel using thread pool.
        
        Args:
            cves: List of CVE dicts to process
            max_concurrent: Maximum concurrent workers
            
        Returns:
            List of remediation results
        """
        if not cves:
            return []
        
        results = []
        total = len(cves)
        
        logger.info(f"🔧 Processing {total} CVEs with {max_concurrent} concurrent workers")
        
        # Process in batches to avoid overwhelming the API
        batch_size = max_concurrent
        for i in range(0, total, batch_size):
            batch = cves[i:i + batch_size]
            batch_num = (i // batch_size) + 1
            total_batches = (total + batch_size - 1) // batch_size
            
            logger.info(f"📦 Processing batch {batch_num}/{total_batches} ({len(batch)} CVEs)")
            
            # Submit batch for parallel processing
            futures = {}
            for cve in batch:
                agent = RemediationWorkerAgent()
                future = self.executor.submit(agent.generate_remediation, cve)
                futures[future] = cve.get("cve_id", "UNKNOWN")
            
            # Wait for batch to complete
            for future in as_completed(futures, timeout=90):
                cve_id = futures[future]
                try:
                    result = future.result(timeout=60)  # 60s timeout per CVE
                    results.append(result)
                    logger.info(f"✅ Completed {len(results)}/{total}: {cve_id}")
                except Exception as e:
                    logger.error(f"❌ Failed to process {cve_id}: {e}")
                    # Add stub remediation for failed CVEs
                    results.append({
                        "cve_id": cve_id,
                        "severity": "Unknown",
                        "priority": "Immediate (24-48 hours)",
                        "steps": [f"Review and remediate {cve_id}"],
                        "references": ["NVD"]
                    })
        
        logger.info(f"✅ Parallel remediation complete: {len(results)}/{total} successful")
        return results
    
    def __del__(self):
        """Cleanup thread pool on deletion."""
        self.executor.shutdown(wait=False)


class ReportBuilderAgent:
    """
    Agent that assembles final report from sub-agent outputs.
    No heavy AI calls - just structuring and formatting data.
    """
    
    def build(
        self,
        parsed_scan: Dict,
        analysis: Dict,
        risk: Dict,
        remediations: List[Dict]
    ) -> Dict:
        """
        Build final report from all sub-agent outputs.
        
        Args:
            parsed_scan: Original parsed scan data
            analysis: Output from SeverityAnalysisAgent
            risk: Output from RiskScoringAgent
            remediations: Output from RemediationAgentPool
            
        Returns:
            Complete structured report dictionary
        """
        logger.info("📝 Building final report")
        
        host = parsed_scan.get("host", {})
        findings = parsed_scan.get("findings", [])
        
        # Build findings list with remediation
        final_findings = []
        remediation_map = {r.get("cve_id"): r for r in remediations}
        
        for finding in findings:
            cve_id = finding.get("cve_id", "UNKNOWN")
            
            # Find matching remediation
            remediation = remediation_map.get(cve_id)
            
            # Get severity from analysis
            severity = self._get_severity(cve_id, analysis)
            
            # Build finding entry using AI-generated data
            if remediation:
                # Use rich AI-generated remediation data
                finding_entry = {
                    "cve_id": cve_id,
                    "title": f"Vulnerability: {cve_id}",
                    "severity": severity,
                    "description": finding.get("description", "No description available")[:500],
                    "impact": self._extract_impact_from_remediation(remediation, severity),
                    "recommendation": remediation,  # Keep full structured remediation
                    "references": remediation.get("references", ["NVD", "NIST"])
                }
            else:
                # Fallback for CVEs without detailed remediation
                finding_entry = {
                    "cve_id": cve_id,
                    "title": f"Vulnerability: {cve_id}",
                    "severity": severity,
                    "description": finding.get("description", "No description available")[:500],
                    "impact": f"{severity} severity vulnerability requiring security assessment and remediation",
                    "recommendation": {
                        "priority": "Immediate (24-48 hours)" if severity in ["Critical", "High"] else "Short-term (1-2 weeks)",
                        "steps": [f"Review {cve_id} at https://nvd.nist.gov/vuln/detail/{cve_id}", "Apply vendor security patches"],
                        "references": ["NVD", "NIST"]
                    },
                    "references": ["NVD", "NIST"]
                }
            
            final_findings.append(finding_entry)
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(host, analysis, risk)
        
        # Generate overall recommendations
        overall_recommendations = self._generate_overall_recommendations(analysis, remediations)
        
        # Extract severity counts for template
        critical_count = analysis.get("critical", {}).get("count", 0)
        high_count = analysis.get("high", {}).get("count", 0)
        medium_count = analysis.get("medium", {}).get("count", 0)
        low_count = analysis.get("low", {}).get("count", 0)
        
        # Extract client/hostname info
        hostname = host.get("hostname", "Unknown")
        
        # Assemble final report
        report = {
            "executive_summary": executive_summary,
            "system_overview": f"Hostname: {hostname}, OS: {host.get('os', 'Unknown')} {host.get('os_version', '')}",
            "findings": final_findings,
            "recommendations": overall_recommendations,
            "risk_score": risk.get("risk_score", 0.0),
            "risk_level": risk.get("risk_level", "Unknown"),
            "severity_breakdown": {
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count,
                "info": 0
            },
            # Individual counts for template convenience
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "info_count": 0,
            "client_name": hostname  # Use hostname as client name
        }
        
        logger.info("✅ Final report assembled")
        return report
    
    def _get_severity(self, cve_id: str, analysis: Dict) -> str:
        """Get severity level for a specific CVE."""
        for level in ["critical", "high", "medium", "low"]:
            cves = analysis.get(level, {}).get("cves", [])
            if cve_id in cves:
                return level.capitalize()
        return "Unknown"
    
    def _extract_impact_from_remediation(self, remediation: Dict, severity: str) -> str:
        """
        Extract or generate impact assessment from remediation data.
        Uses the AI-generated steps to infer impact.
        """
        steps = remediation.get("steps", [])
        priority = remediation.get("priority", "")
        
        # Build impact based on AI-generated remediation urgency and steps
        if priority and "Immediate" in priority:
            impact_base = f"{severity} severity vulnerability with immediate exploitation risk."
        elif priority and "Short-term" in priority:
            impact_base = f"{severity} severity vulnerability requiring prompt attention."
        else:
            impact_base = f"{severity} severity vulnerability."
        
        # Add context from first step if available
        if steps and len(steps) > 0:
            first_step = str(steps[0])[:150]
            # Infer impact from remediation type
            if "isolate" in first_step.lower() or "disconnect" in first_step.lower():
                return f"{impact_base} Poses significant risk requiring immediate network isolation."
            elif "upgrade" in first_step.lower() or "patch" in first_step.lower():
                return f"{impact_base} Known vulnerability with available security patches."
            elif "firewall" in first_step.lower() or "block" in first_step.lower():
                return f"{impact_base} Requires immediate access controls to prevent exploitation."
        
        return f"{impact_base} Requires security assessment and remediation."
    
    def _generate_executive_summary(self, host: Dict, analysis: Dict, risk: Dict) -> str:
        """Generate executive summary from analysis results."""
        hostname = host.get("hostname", "system")
        total = analysis.get("total", 0)
        critical = analysis.get("critical", {}).get("count", 0)
        high = analysis.get("high", {}).get("count", 0)
        risk_score = risk.get("risk_score", 0.0)
        risk_level = risk.get("risk_level", "Unknown")
        
        return (
            f"Security assessment for {hostname} identified {total} vulnerabilities "
            f"with an overall risk score of {risk_score}/10.0 ({risk_level}). "
            f"The scan found {critical} critical and {high} high-severity vulnerabilities "
            f"requiring immediate attention. Prioritized remediation is recommended to "
            f"reduce security exposure and protect against potential exploitation."
        )
    
    def _generate_overall_recommendations(self, analysis: Dict, remediations: List[Dict]) -> str:
        """
        Generate prioritized overall recommendations from AI-generated remediation data.
        Uses actual remediation priorities and steps instead of generic templates.
        """
        critical = analysis.get("critical", {}).get("count", 0)
        high = analysis.get("high", {}).get("count", 0)
        immediate_count = critical + high
        
        recommendations = []
        
        # Extract priority-based recommendations from AI-generated remediations
        immediate_actions = []
        short_term_actions = []
        long_term_actions = []
        
        for remediation in remediations:
            priority = remediation.get("priority", "")
            steps = remediation.get("steps", [])
            cve_id = remediation.get("cve_id", "")
            
            if steps:
                # Extract first 1-2 key actions from AI recommendations
                key_action = str(steps[0]) if len(steps) > 0 else ""
                
                if "Immediate" in priority:
                    if key_action and cve_id:
                        immediate_actions.append(f"{cve_id}: {key_action[:150]}")
                elif "Short-term" in priority:
                    if key_action:
                        short_term_actions.append(key_action[:150])
                else:
                    if key_action:
                        long_term_actions.append(key_action[:150])
        
        # Build recommendations from AI-generated data
        if immediate_count > 0 and immediate_actions:
            recommendations.append(
                f"**Immediate Priority ({immediate_count} CVEs)**: " + 
                " | ".join(immediate_actions[:3])  # Top 3 immediate actions
            )
        elif immediate_count > 0:
            recommendations.append(
                f"**Immediate Priority**: Address {immediate_count} critical/high severity "
                f"vulnerabilities within 24-48 hours based on detailed remediation steps provided above."
            )
        
        if short_term_actions:
            recommendations.append(
                "**Short-term Actions**: " + " | ".join(set(short_term_actions[:2]))  # Unique top 2
            )
        
        if long_term_actions:
            recommendations.append(
                "**Long-term Improvements**: " + " | ".join(set(long_term_actions[:2]))  # Unique top 2
            )
        
        # Add general best practices only if no AI recommendations available
        if not recommendations:
            recommendations.append(
                "**Patch Management**: Implement a systematic patch management process to "
                "regularly apply security updates following vendor advisories."
            )
            recommendations.append(
                "**Vulnerability Scanning**: Conduct regular automated vulnerability scans "
                "(weekly or monthly) to identify new vulnerabilities promptly."
            )
        
        return " ".join(recommendations)


# ==================== ORCHESTRATOR ====================

class SecurityReportOrchestrator:
    """
    Main orchestrator that coordinates multiple specialized agents.
    
    Workflow:
    1. Severity Analysis (fast, single agent)
    2. Risk Scoring (fast, single agent)
    3. Parallel Remediation (multiple workers)
    4. Report Assembly (fast, formatting only)
    """
    
    def __init__(self):
        self.analysis_agent = SeverityAnalysisAgent()
        self.risk_agent = RiskScoringAgent()
        self.remediation_pool = RemediationAgentPool(max_workers=3)
        self.report_builder = ReportBuilderAgent()
    
    def generate_report(self, parsed_scan: Dict) -> Dict:
        """
        Orchestrate multi-agent workflow for report generation.
        
        Args:
            parsed_scan: Parsed scan data with host info and findings
            
        Returns:
            Complete security assessment report
        """
        try:
            logger.info("🎯 Starting multi-agent report generation")
            
            # Step 1: Quick Severity Analysis (single agent, ~5-10s)
            logger.info("📊 Step 1: Analyzing vulnerabilities")
            analysis_result = self.analysis_agent.analyze(parsed_scan)
            
            # Step 2: Risk Scoring (local calculation, instant)
            logger.info("📈 Step 2: Calculating risk scores")
            risk_result = self.risk_agent.calculate_risk(analysis_result)
            
            # Step 3: Parallel Remediation (multiple agents, ~20-30s for 5 CVEs)
            logger.info("🔧 Step 3: Generating remediation (parallel)")
            priority_cves = self._get_priority_cves(parsed_scan, analysis_result)
            
            if priority_cves:
                remediation_results = self.remediation_pool.process_parallel(
                    priority_cves,
                    max_concurrent=3  # Process 3 CVEs at a time
                )
            else:
                remediation_results = []
            
            # Step 4: Build Final Report (formatting only, instant)
            logger.info("📝 Step 4: Building final report")
            final_report = self.report_builder.build(
                parsed_scan=parsed_scan,
                analysis=analysis_result,
                risk=risk_result,
                remediations=remediation_results
            )
            
            logger.info("✅ Multi-agent report generation complete")
            return final_report
            
        except Exception as e:
            logger.error(f"❌ Orchestrator error: {e}", exc_info=True)
            # Fallback to basic report
            return self._generate_fallback_report(parsed_scan)
    
    def _get_priority_cves(self, parsed_scan: Dict, analysis_result: Dict) -> List[Dict]:
        """Extract critical and high severity CVEs for detailed remediation."""
        priority_cves = []
        findings = parsed_scan.get("findings", [])
        
        # Get critical CVEs
        critical_cves = analysis_result.get("critical", {}).get("cves", [])
        for cve_id in critical_cves:
            priority_cves.append({
                "cve_id": cve_id,
                "severity": "Critical",
                "description": _get_cve_description(cve_id, findings)
            })
        
        # Get high CVEs
        high_cves = analysis_result.get("high", {}).get("cves", [])
        for cve_id in high_cves:
            priority_cves.append({
                "cve_id": cve_id,
                "severity": "High",
                "description": _get_cve_description(cve_id, findings)
            })
        
        logger.info(f"🎯 Identified {len(priority_cves)} priority CVEs for detailed remediation")
        return priority_cves
    
    def _generate_fallback_report(self, parsed_scan: Dict) -> Dict:
        """Generate basic fallback report when orchestration fails."""
        host = parsed_scan.get("host", {})
        findings = parsed_scan.get("findings", [])
        
        logger.warning("Using fallback report generation")
        
        return {
            "executive_summary": f"Security scan for {host.get('hostname', 'system')} identified {len(findings)} vulnerabilities requiring attention.",
            "system_overview": f"Hostname: {host.get('hostname', 'Unknown')}, OS: {host.get('os', 'Unknown')}",
            "findings": [
                {
                    "cve_id": f.get("cve_id", "UNKNOWN"),
                    "title": f"Vulnerability: {f.get('cve_id', 'UNKNOWN')}",
                    "severity": "High",
                    "description": f.get("description", "No description")[:300],
                    "impact": "Requires security assessment",
                    "recommendation": "Review and apply vendor security patches",
                    "references": ["NVD", "NIST"]
                }
                for f in findings[:10]  # Limit to 10 findings in fallback
            ],
            "recommendations": "Prioritize patching critical and high-severity vulnerabilities. Implement regular vulnerability scanning and patch management procedures.",
            "risk_score": 7.0,
            "risk_level": "High",
            "severity_breakdown": {
                "critical": 0,
                "high": len(findings),
                "medium": 0,
                "low": 0,
                "info": 0
            }
        }

