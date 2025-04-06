import os
import base64
import aiohttp
import logging
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP


load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

if not VIRUSTOTAL_API_KEY:
    raise ValueError("❌ VIRUSTOTAL_API_KEY is missing. Please set it in your .env file.")

BASE_URL = "https://www.virustotal.com/api/v3"


mcp = FastMCP("VirusTotal MCP Server")


logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

async def fetch_vt_data(endpoint: str) -> dict:
    """Fetch data from VirusTotal API asynchronously."""
    url = f"{BASE_URL}/{endpoint}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    error_message = f"❌ API request failed ({response.status}): {await response.text()}"
                    logging.error(error_message)
                    return {"error": error_message}
        except aiohttp.ClientError as e:
            logging.error(f"❌ Network error: {e}")
            return {"error": "Network error while fetching data from VirusTotal."}

def format_response(title: str, data: dict, fields: list) -> str:
    """Format VirusTotal API responses into readable text."""
    if "error" in data:
        return f"❌ Error: {data['error']}"

    attributes = data.get("data", {}).get("attributes", {})

    if not attributes:
        return f"⚠️ No valid data found for {title}."

    response_lines = [f"🔍 **{title} Report** 🔍\n"]
    for field, label in fields:
        value = attributes.get(field, "N/A")
        response_lines.append(f"**{label}:** {value}")

    return "\n".join(response_lines)

# ----------------------------- VirusTotal API Tools -----------------------------

@mcp.tool("vt_ip_report")
async def vt_ip_report(ip: str) -> str:
    """Get a VirusTotal report for an IP address."""
    data = await fetch_vt_data(f"ip_addresses/{ip}")
    return format_response("IP Address", data, [
        ("reputation", "Reputation"),
        ("continent", "Continent"),
        ("country", "Country"),
        ("asn", "ASN"),
        ("as_owner", "AS Owner"),
    ])

@mcp.tool("vt_domain_report")
async def vt_domain_report(domain: str) -> str:
    """Get a VirusTotal report for a domain."""
    data = await fetch_vt_data(f"domains/{domain}")
    return format_response("Domain", data, [
        ("reputation", "Reputation"),
        ("registrar", "Registrar"),
        ("tld", "Top-Level Domain"),
    ])

@mcp.tool("vt_filehash_report")
async def vt_filehash_report(file_hash: str) -> str:
    """Get a VirusTotal report for a file hash."""
    data = await fetch_vt_data(f"files/{file_hash}")
    return format_response("File", data, [
        ("type_extension", "File Type"),
        ("reputation", "Reputation"),
    ])

@mcp.tool("vt_url_report")
async def vt_url_report(url: str) -> str:
    """Get a VirusTotal report for a URL."""
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    data = await fetch_vt_data(f"urls/{encoded_url}")
    return format_response("URL", data, [
        ("last_final_url", "Final URL"),
        ("reputation", "Reputation"),
        ("times_submitted", "Times Submitted"),
        ("total_votes", "Total Votes"),
    ])

@mcp.tool("vt_threat_categories")
async def vt_threat_categories() -> str:
    """Get popular threat categories from VirusTotal."""
    data = await fetch_vt_data("popular_threat_categories")

    categories = data.get("data", [])

    if not isinstance(categories, list):
        return "❌ Error: Unexpected response format from VirusTotal."

    if not categories:
        return "🔍 No threat categories found."

    category_list = "\n".join([f"🔹 {cat}" for cat in categories])
    return f"🔍 **Threat Categories Report** 🔍\n{category_list}"

@mcp.tool("vt_attack_tactic")
async def vt_attack_tactic(tactic_id: str) -> str:
    """Get details about a specific attack tactic."""
    data = await fetch_vt_data(f"attack_tactics/{tactic_id}")
    return format_response("Attack Tactic", data, [
        ("name", "Name"),
        ("description", "Description"),
    ])

@mcp.tool("vt_attack_technique")
async def vt_attack_technique(technique_id: str) -> str:
    """Get details about a specific attack technique."""
    data = await fetch_vt_data(f"attack_techniques/{technique_id}")
    return format_response("Attack Technique", data, [
        ("name", "Name"),
        ("description", "Description"),
    ])

@mcp.tool("vt_comments")
async def vt_comments(tag: str) -> str:
    """Get comments related to a specific tag on VirusTotal."""
    data = await fetch_vt_data(f"comments?filter=tag%3A{tag}&limit=1")
    comments = data.get("data", [])

    if not comments:
        return "No comments found."

    comment_texts = "\n".join([f"💬 {c.get('attributes', {}).get('text', 'N/A')}" for c in comments])
    return f"🔍 **VirusTotal Comments** 🔍\n{comment_texts}"

@mcp.tool("vt_behavior")
async def vt_behavior(file_hash: str) -> str:
    """Get the behavior summary of a file from VirusTotal."""
    data = await fetch_vt_data(f"files/{file_hash}/behaviour_summary")
    attributes = data.get("data", {}).get("attributes", {})
    behavior_summary = attributes.get("summary", "No behavior data available.")
    return f"🔍 **File Behavior Summary** 🔍\n{behavior_summary}"

# ----------------------------- MCP Server Start -----------------------------
if __name__ == "__main__":
    logging.info("🚀 Starting VirusTotal MCP Server...")
    mcp.run()
