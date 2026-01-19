

""" Splunk Logs
   ↓
LangChain Log Parser Agent
   ↓
Threat Intel Agent
   ↓
Correlation & Behavior Agent
   ↓
Decision Agent
   ↓
SOAR / Ticket / Slack / PagerDuty

 """

# import dependencies 
from langchain_openai import ChatOpenAI
from parserAgent import parse_log
from threatdetectionAgent import threat_intel_lookup
from behaviourCorrelationAgent import behavior_analysis
from verdictAgent import soc_decision
from dotenv import load_dotenv

import os


load_dotenv()

apikey = os.getenv('chatgptapikey')
print(apikey)

#Initialize llm
llm = ChatOpenAI(api_key=apikey , model="gpt-4o-mini", temperature=0)

# Orchestrator (Agentic Workflow)

def soc_agent_pipeline(raw_log: str):
    parsed = parse_log(raw_log,llm)
    intel = threat_intel_lookup(parsed.src_ip)
    behavior = behavior_analysis(parsed.src_ip)
    verdict = soc_decision(parsed, intel, behavior)

    return {
        "parsed_log": parsed.dict(),
        "threat_intel": intel.dict(),
        "behavior": behavior.dict(),
        "soc_verdict": verdict.dict()
    }



if __name__ == "__main__":
  splunk_log = """
  _time=2026-01-18T14:32:11Z
  user=john.doe
  src_ip=185.220.101.45
  host=web-prod-01
  auth_method=ssh
  message="Failed password for invalid user"
  """

  result = soc_agent_pipeline(splunk_log)
  
  print(result)