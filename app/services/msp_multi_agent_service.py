"""
LangGraph Multi-Agent MSP Report Generation System

This module implements a LangGraph-based multi-agent architecture for generating
MSP Cyber Hygiene & Credential Exposure Reports with intelligent data splitting 
and parallel processing.

Architecture:
1. Data Splitter Node - Splits data by type (credentials, software, system info)
2. Parallel Processing:
   - Credential Analysis Node - Analyzes browser, OS, and app credentials
   - Software Risk Node - Analyzes installed software vulnerabilities
   - System Security Node - Analyzes user accounts and system configuration
3. Risk Scoring Node - Calculates overall endpoint risk score
4. Remediation Node - Generates prioritized remediation steps
5. Report Builder Node - Assembles final MSP report

Key Benefits:
- Context Management: Each agent receives only relevant data portions
- Parallel Execution: Multiple analyses run simultaneously
- Professional Output: MSP-ready format with actionable insights
"""

from __future__ import annotations

import json
import logging
import operator
from typing import Dict, List, Any, Optional, TypedDict, Annotated
from datetime import datetime

from langchain_google_genai import ChatGoogleGenerativeAI
import google.generativeai as genai
from langgraph.graph import StateGraph, END

from app.core.config import settings

logger = logging.getLogger(__name__)

# Configure Gemini
genai.configure(api_key=settings.gemini_api_key)


# ==================== LANGGRAPH STATE SCHEMA ====================

class MSPAnalysisState(TypedDict):
    """State schema for MSP LangGraph workflow."""
    # Input data
    parsed_data: Dict
    
    # Split data
    endpoint_info: Dict
    credentials_data: Dict
    software_data: Dict
    system_data: Dict
    
    # Agent outputs
    credential_analysis: Dict
    software_risk_analysis: Dict
    system_security_analysis: Dict
    risk_scoring: Dict
    remediation_plan: Dict
    
    # Final output
    final_report: Dict
    
    # Metadata
    errors: Annotated[List[str], operator.add]


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


# ==================== LANGGRAPH NODE FUNCTIONS ====================

def split_data_node(state: MSPAnalysisState) -> Dict[str, Any]:
    """Split MSP data by type to prevent context overload."""
    parsed_data = state["parsed_data"]
    
    logger.info("MSP Data splitter: Organizing endpoint data")
    
    return {
        "endpoint_info": parsed_data.get("endpoint_info", {}),
        "credentials_data": parsed_data.get("credentials", {}),
        "software_data": parsed_data.get("software", {}),
        "system_data": parsed_data.get("system", {})
    }


def credential_analysis_node(state: MSPAnalysisState) -> Dict[str, Any]:
    """Analyze credential exposure - browsers, OS, and applications."""
    credentials_data = state["credentials_data"]
    endpoint_info = state["endpoint_info"]
    
    logger.info("Credential Analysis Agent: Starting analysis")
    
    agent = CredentialAnalysisAgent()
    result = agent.analyze({
        "credentials": credentials_data,
        "endpoint": endpoint_info.get("hostname", "Unknown")
    })
    
    return {
        "credential_analysis": result
    }


def software_risk_analysis_node(state: MSPAnalysisState) -> Dict[str, Any]:
    """Analyze installed software risks and vulnerabilities."""
    software_data = state["software_data"]
    
    logger.info("Software Risk Agent: Starting analysis")
    
    agent = SoftwareRiskAgent()
    result = agent.analyze({"software": software_data})
    
    return {
        "software_risk_analysis": result
    }


def system_security_analysis_node(state: MSPAnalysisState) -> Dict[str, Any]:
    """Analyze system security configuration and user accounts."""
    system_data = state["system_data"]
    
    logger.info("System Security Agent: Starting analysis")
    
    agent = SystemSecurityAgent()
    result = agent.analyze({"system": system_data})
    
    return {
        "system_security_analysis": result
    }


def risk_scoring_node(state: MSPAnalysisState) -> Dict[str, Any]:
    """Calculate overall endpoint risk score based on all analyses."""
    credential_analysis = state["credential_analysis"]
    software_risk = state["software_risk_analysis"]
    system_security = state["system_security_analysis"]
    
    logger.info("Risk Scoring Agent: Calculating overall risk")
    
    agent = MSPRiskScoringAgent()
    result = agent.calculate_risk({
        "credentials": credential_analysis,
        "software": software_risk,
        "system": system_security
    })
    
    return {
        "risk_scoring": result
    }


def remediation_plan_node(state: MSPAnalysisState) -> Dict[str, Any]:
    """Generate prioritized remediation steps."""
    risk_scoring = state["risk_scoring"]
    credential_analysis = state["credential_analysis"]
    software_risk = state["software_risk_analysis"]
    system_security = state["system_security_analysis"]
    
    logger.info("Remediation Agent: Generating action plan")
    
    agent = RemediationAgent()
    result = agent.generate_plan({
        "risk_score": risk_scoring,
        "credentials": credential_analysis,
        "software": software_risk,
        "system": system_security
    })
    
    return {
        "remediation_plan": result
    }


def report_builder_node(state: MSPAnalysisState) -> Dict[str, Any]:
    """Assemble final MSP report from all agent outputs."""
    logger.info("Report Builder: Assembling final MSP report")
    
    endpoint_info = state["endpoint_info"]
    credential_analysis = state["credential_analysis"]
    software_risk = state["software_risk_analysis"]
    system_security = state["system_security_analysis"]
    risk_scoring = state["risk_scoring"]
    remediation_plan = state["remediation_plan"]
    
    # Build comprehensive report
    final_report = {
        "report_type": "MSP Cyber Hygiene & Credential Exposure",
        "endpoint": endpoint_info.get("hostname", "Unknown"),
        "user": endpoint_info.get("user", "Unknown"),
        "assessment_date": datetime.now().strftime("%Y-%m-%d"),
        
        # Executive Summary
        "executive_summary": {
            "credential_counts": credential_analysis.get("summary", {}),
            "overall_risk_level": risk_scoring.get("overall_risk_level", "UNKNOWN"),
            "risk_score": risk_scoring.get("risk_score", 0),
            "risk_reason": risk_scoring.get("risk_reason", "")
        },
        
        # Detailed Sections
        "credential_exposure": credential_analysis,
        "software_inventory": software_risk,
        "system_security": system_security,
        "risk_scoring_detailed": risk_scoring,
        "remediation_steps": remediation_plan,
        
        # Metadata
        "generated_at": datetime.now().isoformat()
    }
    
    logger.info("✅ MSP Report Builder: Report assembly complete")
    
    return {
        "final_report": final_report
    }


# ==================== AGENT CLASSES ====================

class CredentialAnalysisAgent:
    """Agent specialized in analyzing credential exposure."""
    
    def __init__(self):
        self.llm = ChatGoogleGenerativeAI(
            model="gemini-2.0-flash-exp",
            temperature=0.3,
            google_api_key=settings.gemini_api_key
        )
    
    def analyze(self, data: Dict) -> Dict:
        """Analyze browser, OS, and application credentials."""
        prompt = f"""You are an MSP security analyst specializing in credential exposure analysis.

Analyze the following credential data and provide a detailed security assessment:

Credentials Data:
{json.dumps(data, indent=2)}

Provide your analysis in the following JSON format:
{{
    "summary": {{
        "total_credentials": <number>,
        "browser_credentials": <number>,
        "os_credentials": <number>,
        "app_credentials": <number>
    }},
    "browser_exposure": [
        {{
            "browser": "<browser name>",
            "url": "<URL>",
            "username": "<username>",
            "risk_level": "High/Medium/Low",
            "risk_reason": "<why this is risky>"
        }}
    ],
    "os_credentials": [
        {{
            "type": "WiFi/VPN/etc",
            "name": "<connection name>",
            "account": "<account if applicable>",
            "risk_level": "Critical/High/Medium/Low",
            "risk_reason": "<why this is risky>"
        }}
    ],
    "app_credentials": [
        {{
            "application": "<app name>",
            "username": "<username>",
            "risk_level": "High/Medium/Low",
            "risk_reason": "<why this is risky>"
        }}
    ],
    "key_insights": ["<insight 1>", "<insight 2>", "..."]
}}

Focus on:
- Identifying high-value targets (VPN, corporate email, developer accounts)
- Explaining MSP-relevant risks
- Professional language for client communication
"""
        
        try:
            response = self.llm.invoke(prompt)
            result = _extract_json_from_text(response.content)
            
            if result:
                logger.info(f"Credential Analysis: Found {result.get('summary', {}).get('total_credentials', 0)} total credentials")
                return result
            else:
                logger.warning("Credential Analysis: Could not parse JSON, returning stub")
                return self._generate_stub_analysis(data)
                
        except Exception as e:
            logger.error(f"Credential Analysis error: {e}", exc_info=True)
            return self._generate_stub_analysis(data)
    
    def _generate_stub_analysis(self, data: Dict) -> Dict:
        """Generate basic analysis when AI fails."""
        creds = data.get("credentials", {})
        browsers = creds.get("browsers", [])
        os_creds = creds.get("os", [])
        apps = creds.get("apps", [])
        
        return {
            "summary": {
                "total_credentials": len(browsers) + len(os_creds) + len(apps),
                "browser_credentials": len(browsers),
                "os_credentials": len(os_creds),
                "app_credentials": len(apps)
            },
            "browser_exposure": [],
            "os_credentials": [],
            "app_credentials": [],
            "key_insights": ["Analysis pending - awaiting AI response"]
        }


class SoftwareRiskAgent:
    """Agent specialized in analyzing installed software risks."""
    
    def __init__(self):
        self.llm = ChatGoogleGenerativeAI(
            model="gemini-2.0-flash-exp",
            temperature=0.3,
            google_api_key=settings.gemini_api_key
        )
    
    def analyze(self, data: Dict) -> Dict:
        """Analyze installed software for security risks."""
        prompt = f"""You are an MSP security analyst specializing in software vulnerability assessment.

Analyze the following installed software inventory:

Software Data:
{json.dumps(data, indent=2)}

Provide your analysis in the following JSON format:
{{
    "total_software": <number>,
    "high_risk_software": [
        {{
            "name": "<software name>",
            "version": "<version>",
            "risk_level": "High/Medium",
            "risk_reason": "<security concern>",
            "recommendation": "<action to take>"
        }}
    ],
    "outdated_software": [
        {{
            "name": "<software name>",
            "version": "<current version>",
            "issue": "<what's wrong>",
            "recommendation": "<update action>"
        }}
    ],
    "notable_software": [
        {{
            "name": "<software name>",
            "category": "<type of software>",
            "notes": "<relevant observation>"
        }}
    ],
    "key_insights": ["<insight 1>", "<insight 2>", "..."]
}}

Focus on:
- End-of-life (EOL) software with known CVEs
- High attack surface applications
- Professional recommendations for MSP clients
"""
        
        try:
            response = self.llm.invoke(prompt)
            result = _extract_json_from_text(response.content)
            
            if result:
                logger.info(f"Software Risk: Analyzed {result.get('total_software', 0)} software packages")
                return result
            else:
                logger.warning("Software Risk: Could not parse JSON, returning stub")
                return self._generate_stub_analysis(data)
                
        except Exception as e:
            logger.error(f"Software Risk error: {e}", exc_info=True)
            return self._generate_stub_analysis(data)
    
    def _generate_stub_analysis(self, data: Dict) -> Dict:
        """Generate basic analysis when AI fails."""
        software = data.get("software", [])
        
        return {
            "total_software": len(software),
            "high_risk_software": [],
            "outdated_software": [],
            "notable_software": [],
            "key_insights": ["Analysis pending - awaiting AI response"]
        }


class SystemSecurityAgent:
    """Agent specialized in system security configuration analysis."""
    
    def __init__(self):
        self.llm = ChatGoogleGenerativeAI(
            model="gemini-2.0-flash-exp",
            temperature=0.3,
            google_api_key=settings.gemini_api_key
        )
    
    def analyze(self, data: Dict) -> Dict:
        """Analyze system user accounts and security configuration."""
        prompt = f"""You are an MSP security analyst specializing in system security configuration.

Analyze the following system information:

System Data:
{json.dumps(data, indent=2)}

Provide your analysis in the following JSON format:
{{
    "user_analysis": {{
        "username": "<username>",
        "has_admin": <true/false>,
        "last_login": "<date>",
        "security_assessment": "<assessment>",
        "risk_level": "Low/Medium/High"
    }},
    "login_security": {{
        "concerns": ["<concern 1>", "<concern 2>"],
        "positive_indicators": ["<good thing 1>", "<good thing 2>"]
    }},
    "system_configuration": {{
        "observations": ["<observation 1>", "<observation 2>"]
    }},
    "key_insights": ["<insight 1>", "<insight 2>", "..."]
}}

Focus on:
- Admin privileges and lateral movement risk
- Account activity patterns
- Security configuration gaps
"""
        
        try:
            response = self.llm.invoke(prompt)
            result = _extract_json_from_text(response.content)
            
            if result:
                logger.info("System Security: Analysis complete")
                return result
            else:
                logger.warning("System Security: Could not parse JSON, returning stub")
                return self._generate_stub_analysis(data)
                
        except Exception as e:
            logger.error(f"System Security error: {e}", exc_info=True)
            return self._generate_stub_analysis(data)
    
    def _generate_stub_analysis(self, data: Dict) -> Dict:
        """Generate basic analysis when AI fails."""
        return {
            "user_analysis": {},
            "login_security": {
                "concerns": [],
                "positive_indicators": []
            },
            "system_configuration": {
                "observations": []
            },
            "key_insights": ["Analysis pending - awaiting AI response"]
        }


class MSPRiskScoringAgent:
    """Agent specialized in calculating MSP endpoint risk scores."""
    
    def __init__(self):
        self.llm = ChatGoogleGenerativeAI(
            model="gemini-2.0-flash-exp",
            temperature=0.3,
            google_api_key=settings.gemini_api_key
        )
    
    def calculate_risk(self, data: Dict) -> Dict:
        """Calculate comprehensive risk score."""
        prompt = f"""You are an MSP security analyst calculating endpoint risk scores.

Based on the following analysis data:

{json.dumps(data, indent=2)}

Provide a comprehensive risk assessment in the following JSON format:
{{
    "overall_risk_level": "CRITICAL/HIGH/MEDIUM/LOW",
    "risk_score": <0-10 float>,
    "risk_reason": "<brief explanation of overall risk>",
    "category_scores": {{
        "credential_exposure": <0-10>,
        "password_hygiene": <0-10>,
        "software_risk": <0-10>,
        "user_account_security": <0-10>
    }},
    "scoring_breakdown": {{
        "credential_exposure": "<explanation>",
        "password_hygiene": "<explanation>",
        "software_risk": "<explanation>",
        "user_account_security": "<explanation>"
    }},
    "risk_factors": [
        "<major risk factor 1>",
        "<major risk factor 2>",
        "..."
    ]
}}

Scoring Guidelines:
- 9-10: Critical risk requiring immediate action
- 7-8: High risk requiring urgent attention
- 5-6: Medium risk requiring scheduled remediation
- 3-4: Low risk with recommended improvements
- 0-2: Minimal risk with good security posture

Focus on MSP context: stored VPN passwords, corporate credentials, high-value accounts.
"""
        
        try:
            response = self.llm.invoke(prompt)
            result = _extract_json_from_text(response.content)
            
            if result:
                logger.info(f"Risk Scoring: Overall risk level = {result.get('overall_risk_level', 'UNKNOWN')}")
                return result
            else:
                logger.warning("Risk Scoring: Could not parse JSON, returning stub")
                return self._generate_stub_scoring()
                
        except Exception as e:
            logger.error(f"Risk Scoring error: {e}", exc_info=True)
            return self._generate_stub_scoring()
    
    def _generate_stub_scoring(self) -> Dict:
        """Generate basic scoring when AI fails."""
        return {
            "overall_risk_level": "MEDIUM",
            "risk_score": 5.0,
            "risk_reason": "Analysis pending",
            "category_scores": {
                "credential_exposure": 5.0,
                "password_hygiene": 5.0,
                "software_risk": 5.0,
                "user_account_security": 5.0
            },
            "scoring_breakdown": {},
            "risk_factors": []
        }


class RemediationAgent:
    """Agent specialized in generating remediation plans."""
    
    def __init__(self):
        self.llm = ChatGoogleGenerativeAI(
            model="gemini-2.0-flash-exp",
            temperature=0.4,
            google_api_key=settings.gemini_api_key
        )
    
    def generate_plan(self, data: Dict) -> Dict:
        """Generate prioritized remediation steps."""
        prompt = f"""You are an MSP security consultant creating remediation action plans.

Based on the following security analysis:

{json.dumps(data, indent=2)}

Create a prioritized remediation plan in the following JSON format:
{{
    "immediate_actions": [
        {{
            "priority": "Critical",
            "action": "<specific action>",
            "reason": "<why this is critical>",
            "steps": ["<step 1>", "<step 2>", "..."]
        }}
    ],
    "medium_priority": [
        {{
            "priority": "Medium",
            "action": "<specific action>",
            "reason": "<why this matters>",
            "steps": ["<step 1>", "<step 2>", "..."]
        }}
    ],
    "low_priority": [
        {{
            "priority": "Low",
            "action": "<specific action>",
            "reason": "<benefit>",
            "steps": ["<step 1>", "<step 2>", "..."]
        }}
    ],
    "msp_recommendations": [
        "<recommendation for MSP use>",
        "<recommendation for client presentation>",
        "..."
    ]
}}

Focus on:
- Actionable, specific steps
- Business impact justification
- MSP service opportunities
- Client communication points
"""
        
        try:
            response = self.llm.invoke(prompt)
            result = _extract_json_from_text(response.content)
            
            if result:
                immediate_count = len(result.get("immediate_actions", []))
                logger.info(f"Remediation: Generated {immediate_count} immediate actions")
                return result
            else:
                logger.warning("Remediation: Could not parse JSON, returning stub")
                return self._generate_stub_plan()
                
        except Exception as e:
            logger.error(f"Remediation error: {e}", exc_info=True)
            return self._generate_stub_plan()
    
    def _generate_stub_plan(self) -> Dict:
        """Generate basic plan when AI fails."""
        return {
            "immediate_actions": [],
            "medium_priority": [],
            "low_priority": [],
            "msp_recommendations": ["Comprehensive security review recommended"]
        }


# ==================== ORCHESTRATOR ====================

class MSPReportOrchestrator:
    """
    LangGraph-based orchestrator for MSP report generation.
    
    Workflow:
    1. Data Splitting - Separate credentials, software, system data
    2. Parallel Processing:
       - Credential Analysis
       - Software Risk Analysis
       - System Security Analysis
    3. Risk Scoring - Calculate overall endpoint risk
    4. Remediation Planning - Generate action items
    5. Report Assembly - Create final MSP report
    """
    
    def __init__(self):
        self.graph = self._build_graph()
    
    def _build_graph(self) -> StateGraph:
        """Build LangGraph workflow with parallel execution."""
        workflow = StateGraph(MSPAnalysisState)
        
        # Add nodes
        workflow.add_node("split_data", split_data_node)
        workflow.add_node("analyze_credentials", credential_analysis_node)
        workflow.add_node("analyze_software", software_risk_analysis_node)
        workflow.add_node("analyze_system", system_security_analysis_node)
        workflow.add_node("score_risk", risk_scoring_node)
        workflow.add_node("generate_remediation", remediation_plan_node)
        workflow.add_node("build_report", report_builder_node)
        
        # Define workflow edges
        workflow.set_entry_point("split_data")
        
        # Parallel execution: split_data -> three parallel analyses
        workflow.add_edge("split_data", "analyze_credentials")
        workflow.add_edge("split_data", "analyze_software")
        workflow.add_edge("split_data", "analyze_system")
        
        # All three analyses must complete before risk scoring
        workflow.add_edge("analyze_credentials", "score_risk")
        workflow.add_edge("analyze_software", "score_risk")
        workflow.add_edge("analyze_system", "score_risk")
        
        # Risk scoring -> remediation planning
        workflow.add_edge("score_risk", "generate_remediation")
        
        # Remediation -> final report
        workflow.add_edge("generate_remediation", "build_report")
        
        # End workflow
        workflow.add_edge("build_report", END)
        
        return workflow.compile()
    
    def generate_report(self, parsed_data: Dict) -> Dict:
        """
        Execute LangGraph workflow to generate MSP report.
        
        Args:
            parsed_data: Parsed MSP data with endpoint info, credentials, software, system data
            
        Returns:
            Complete MSP security report
        """
        try:
            logger.info("🎯 Starting MSP LangGraph multi-agent workflow")
            
            initial_state = MSPAnalysisState(
                parsed_data=parsed_data,
                endpoint_info={},
                credentials_data={},
                software_data={},
                system_data={},
                credential_analysis={},
                software_risk_analysis={},
                system_security_analysis={},
                risk_scoring={},
                remediation_plan={},
                final_report={},
                errors=[]
            )
            
            # Execute graph
            final_state = self.graph.invoke(initial_state)
            
            final_report = final_state["final_report"]
            
            logger.info("✅ MSP LangGraph workflow complete")
            
            return final_report
            
        except Exception as e:
            logger.error(f"❌ MSP LangGraph orchestrator error: {e}", exc_info=True)
            return self._generate_fallback_report(parsed_data)
    
    def _generate_fallback_report(self, parsed_data: Dict) -> Dict:
        """Generate basic fallback report when orchestration fails."""
        endpoint_info = parsed_data.get("endpoint_info", {})
        
        return {
            "report_type": "MSP Cyber Hygiene & Credential Exposure",
            "endpoint": endpoint_info.get("hostname", "Unknown"),
            "user": endpoint_info.get("user", "Unknown"),
            "assessment_date": datetime.now().strftime("%Y-%m-%d"),
            "executive_summary": {
                "credential_counts": {},
                "overall_risk_level": "UNKNOWN",
                "risk_score": 0,
                "risk_reason": "Report generation failed - manual review required"
            },
            "credential_exposure": {},
            "software_inventory": {},
            "system_security": {},
            "risk_scoring_detailed": {},
            "remediation_steps": {},
            "generated_at": datetime.now().isoformat(),
            "error": "Automated analysis failed - manual assessment recommended"
        }

