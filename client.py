# Multiple MCP Servers Client
# This script demonstrates how to connect to multiple MCP servers using the MCP Client.
# It allows you to interact with the servers and utilize their functionalities.
import asyncio
import os
import shutil
from dotenv import load_dotenv
from mcp import ClientSession
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_mcp_adapters.tools import load_mcp_tools
from langgraph.prebuilt import create_react_agent
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

def clear_screen():
    if shutil.get_terminal_size().columns > 0:
        os.system('cls' if os.name == 'nt' else 'clear')

async def chat():
    """Interactive chat session with MCP Servers."""
    clear_screen()
    print("=" * 50)
    print("  🤖 Interactive Agent Demo with MCP Servers  |  Type 'exit' or 'quit' to stop")
    print("=" * 50)

    # Define multi-server configurations.
    # Update the "args" with the correct relative/absolute paths to your server scripts.
    server_configs = {
        "virustotal": {
            "command": "python",
            "args": ["servers/mpc-virustotal-server.py"],
            "transport": "stdio",
        },
        "rstcloud": {
            "command": "python",
            "args": ["servers/mpc-rstcloud-server.py"],
            "transport": "stdio",
        }
    }

    # Connect to both servers using MultiServerMCPClient.
    async with MultiServerMCPClient(server_configs) as client:
        tools = client.get_tools()
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
