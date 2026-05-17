import os
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_community.utilities import SQLDatabase
from langchain_community.agent_toolkits import create_sql_agent

load_dotenv()

# 1. Configure DeepSeek API
os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")
os.environ["OPENAI_API_BASE"] = os.getenv("OPENAI_API_BASE", "https://api.deepseek.com")

# Connect to local Evidence DB (SQLite)
db = SQLDatabase.from_uri("sqlite:///forensic_evidence.db")

# 2. Initialize DeepSeek Model
llm = ChatOpenAI(
    model="deepseek-v4-flash",
    temperature=0.0  # 取证分析严禁模型发挥想象力，设为 0.0 最大程度减少幻觉
)

# 3. Create the ASADF Forensic Agent
# Uses agent_executor_kwargs to ensure the parser error-handling gracefully recovers
forensic_agent = create_sql_agent(
    llm=llm,
    db=db,
    verbose=True,  # Crucial for Live Demo to display the AI's "Chain of Thought" on screen
    agent_type="zero-shot-react-description",
    agent_executor_kwargs={"handle_parsing_errors": True}
)

# 4. Forensic Query and Core Guardrails
base_question = (
    "Please reconstruct a comprehensive forensic timeline of the university data breach incident. "
    "You must cross-correlate evidence across different logs: the initial intrusion traces (evtx_logs), "
    "the credential theft via registry hives backup (prefetch_amcache_logs), the GUI-based user file navigation "
    "(user_behavior_logs), and the final bulk database query and data exfiltration (exfiltration_logs)[cite: 79, 91, 105]. "
    "Every single event mentioned in your final timeline must be strictly anchored to its respective Source_Log_ID."
)

# Structural guardrails to keep the ReAct parser completely stable
format_instruction = (
    "\n\n[CRITICAL FORMAT INSTRUCTION]\n"
    "You must strictly follow the ReAct format block below for every single step of your reasoning process. "
    "Never alter or translate the prefix keywords (Thought, Action, Action Input, Final Answer). "
    "Do not wrap the 'Action Input' in markdown code blocks like ```sql.\n\n"
    "Correct Format Example:\n"
    "Thought: I need to query the logs to find anomalies.\n"
    "Action: sql_db_query\n"
    "Action Input: SELECT * FROM evtx_logs LIMIT 5;\n\n"
    "When you have compiled the final complete forensic timeline report, output it strictly using:\n"
    "Thought: I now know the final answer.\n"
    "Final Answer: [Your detailed comprehensive forensic timeline report here in English]"
)

# Combine the prompt
final_query = base_question + format_instruction

# 5. Run the Forensic Investigation Agent
print("Initializing ASADF Forensic Agentic Engine... [cite: 2, 77]\n")
try:
    response = forensic_agent.invoke({"input": final_query})
    print("\n================ ️ ASADF FORENSIC SYSTEM FINAL REPORT ================\n")
    print(response["output"])
except Exception as e:
    print(f"\n[Execution Error]: {e}")