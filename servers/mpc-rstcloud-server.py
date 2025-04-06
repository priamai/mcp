import os
import base64
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from rstapi import whoisapi, threatfeed, reporthub, noisecontrol, ioclookup
from dateutil import parser
from datetime import datetime

# Load environment variables from .env file
load_dotenv()
RSTCLOUD_API_KEY = os.getenv("RSTCLOUD_API_KEY")
if not RSTCLOUD_API_KEY:
    raise EnvironmentError("RSTCLOUD_API_KEY is not set in environment variables.")

# Initialize API clients for RST Cloud services
whois_client = whoisapi(APIKEY=RSTCLOUD_API_KEY)
ioc_client = ioclookup(APIKEY=RSTCLOUD_API_KEY)
reporthub_client = reporthub(APIKEY=RSTCLOUD_API_KEY)
noise_client = noisecontrol(APIKEY=RSTCLOUD_API_KEY)
threatfeed_client = threatfeed(APIKEY=RSTCLOUD_API_KEY)

# Create the MCP server instance
mcp = FastMCP("RST Cloud MCP Server")

def normalize_date(date_str: str) -> str:
    """Converts a date string into yyyymmdd format."""
    try:
        parsed_date = parser.parse(date_str)
        return parsed_date.strftime('%Y%m%d')
    except ValueError:
        raise ValueError(f"Invalid date format: {date_str}")

def format_dict_report(title: str, data: dict) -> str:
    """
    Formats a dictionary into a human-friendly report.
    Expects 'data' to be a flat dictionary of key/value pairs.
    """
    lines = [f"🔍 **{title} Report** 🔍\n"]
    for key, value in data.items():
        lines.append(f"**{key.capitalize()}:** {value}")
    return "\n".join(lines)

# Tool 1: WHOIS Lookup for Domains
@mcp.tool("rst_whois")
def rst_whois(domain: str) -> str:
    """Retrieve WHOIS information for a domain from RST Cloud."""
    result = whois_client.GetDomainInfo(domain=domain)
    return format_dict_report("WHOIS", result)

# Tool 2: IOC Lookup (IP, Domain, URL, or HASH)
@mcp.tool("rst_ioc_lookup")
def rst_ioc_lookup(ioc_value: str) -> str:
    """Retrieve IOC information from RST Cloud."""
    result = ioc_client.GetIndicator(ioc_value)
    return format_dict_report("IOC Lookup", result)

# Tool 3: Noise Control (Benign Check)
@mcp.tool("rst_noise_control")
def rst_noise_control(ioc_value: str) -> str:
    """Check if a specific IOC is considered benign via RST Cloud Noise Control."""
    result = noise_client.ValueLookup(ioc_value)
    return format_dict_report("Noise Control", result)

# Tool 4: Threat Report Hub (Threat Intelligence Report for a Given Date)
@mcp.tool("rst_report")
def rst_report(date_str: str) -> str:
    """
    Retrieve threat intelligence reports from RST Cloud Report Hub.
    Date must be provided in a format parseable by dateutil (e.g. '2015-03-05').
    """
    norm_date = normalize_date(date_str)
    result = reporthub_client.GetReports(norm_date)
    return format_dict_report("Threat Report", result)

# Tool 5 (Optional): Threat Feed
@mcp.tool("rst_threat_feed")
def rst_threat_feed(ioc_value: str) -> str:
    """
    Retrieve threat feed information for an IOC (IP, Domain, URL, HASH) from RST Cloud Threat Feed.
    Assumes threatfeed client has a GetThreatFeed method.
    """
    result = threatfeed_client.GetThreatFeed(ioc_value)
    return format_dict_report("Threat Feed", result)

if __name__ == "__main__":
    mcp.run()
