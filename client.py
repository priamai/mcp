import asyncio
import os
import shutil
from dotenv import load_dotenv
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from langgraph.prebuilt import create_react_agent
from langchain_mcp_adapters.tools import load_mcp_tools
from langchain_openai import AzureChatOpenAI


load_dotenv()

# ==============================
# ⚠️ LLM Configuration
# Replace this with your preferred LLM. Here, we are using Azure OpenAI.
# ==============================
llm = AzureChatOpenAI(
    api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-08-01-preview"),
    azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
    api_key=os.getenv("AZURE_OPENAI_API_KEY"),
    azure_deployment=os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4"),
)

# MCP Server connection parameters
server_params = StdioServerParameters(
    command="python",
    args=["servers/mpc-virustotal-server.py"],
)


def clear_screen():
    if shutil.get_terminal_size().columns > 0:
        os.system('cls' if os.name == 'nt' else 'clear')

async def chat():
    """Interactive chat session with MCP Server."""
    clear_screen()
    print("=" * 50)
    print("  🤖 Interactive Agent Demo with MCP Servers  |  Type 'exit' or 'quit' to stop")
    print("=" * 50)

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await load_mcp_tools(session)
            agent = create_react_agent(llm, tools)

            conversation_history = []

            while True:
                print("\n" + "-" * 50)
                try:
                    user_input = input("👤 User: ").strip().lower()  
                except KeyboardInterrupt:
                    print("\n📢 Exiting chat. Thank you!\n")
                    break

                if user_input in {"exit", "quit"}:  
                    print("\n📢 Exiting chat. Thank you!\n")
                    break

                
                response = await agent.ainvoke({"messages": user_input})
                bot_reply = response["messages"][-1].content

                
                conversation_history.append(("User", user_input))
                conversation_history.append(("CTI Agent", bot_reply))

                
                print("-" * 50)
                for role, message in conversation_history:
                    role_icon = "👤" if role == "User" else "🤖"
                    print(f"{role_icon} {role}: {message}\n")

if __name__ == "__main__":
    asyncio.run(chat())