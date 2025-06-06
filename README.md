# Model Context Protocol (MCP) for Cybersecurity   

[![smithery badge](https://smithery.ai/badge/@AshfaaqF/mcp-priam-rstcloud)](https://smithery.ai/server/@AshfaaqF/mcp-priam-rstcloud)
[![smithery badge](https://smithery.ai/badge/@AshfaaqF/mcp-priam-virustotal)](https://smithery.ai/server/@AshfaaqF/mcp-priam-virustotal)


## Introduction  
The **Model Context Protocol (MCP)** is a framework designed to standardize and streamline communication between AI agents and various data sources. It facilitates context-aware interactions in a modular and scalable manner. For more details on the philosophy and design of MCP, visit [Model Context Protocol Introduction](https://modelcontextprotocol.io/introduction)


## Overview  
This repository is a collection of MCP servers for cybersecurity. The following server is implemented:  

1. **VirusTotal** - Integrates with VirusTotal's API to fetch real-time threat intelligence data, including reports on IP addresses, domains, file hashes, and URLs, along with threat categories, attack tactics, and techniques.

2. **RSTcloud** - Connects with the RSTcloud API to provide up-to-the-minute threat intelligence. This integration delivers detailed reports on IP addresses, domains, file hashes, and URLs, enriched with threat classifications, attack methods, and techniques..


## Prerequisites
Ensure you have the following installed before proceeding:
- Python 3.11+
- Git
- Virtual environment (venv)

## Setup Instructions

### 1. Clone the Repository
```sh
git clone https://github.com/priamai/mpc.git
cd mpc
```

### 2. Create a Virtual Environment
```sh
python3.11 -m venv venv
source venv/bin/activate  # On macOS/Linux
venv\Scripts\activate    # On Windows
```

### 3. Install Dependencies
```sh
pip install --upgrade pip

pip install -r requirements.txt
```

### 4. Configure API Keys and Environment Variables  
This project requires API keys for VirusTotal and RSTcloud. You must create a `.env` file in the project root and add the required API keys.

#### Example `.env` file for Azure OpenAI:

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key
RSTCLOUD_API_KEY=your_rstcloud_api_key
AZURE_OPENAI_API_KEY=your_azure_openai_api_key
AZURE_OPENAI_ENDPOINT=your_azure_openai_endpoint
AZURE_OPENAI_API_VERSION=your_api_version
AZURE_OPENAI_DEPLOYMENT=your_deployment_name
```

#### Example `.env` file for OpenAI:

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key
OPENAI_API_KEY=your_openai_api_key
```

### 4. Run the MCP Server
```sh
python client.py
```

## Available Tools on VirusTotal Server
The following tools are supported via MCP for VirusTotal:

1. **IP Report** - Fetches details about a given IP address.
2. **Domain Report** - Retrieves reputation and threat data for domains.
3. **File Hash Report** - Provides information about file hashes.
4. **URL Report** - Analyzes and reports on URLs.
5. **Threat Categories** - Lists various threat classifications.
6. **Attack Tactics** - Details about adversary tactics.
7. **Attack Techniques** - Specific attack methodologies.
8. **Comments** - Fetches community comments on analyzed entities.
9. **File Behavior Summary** - Provides insights into file behavior analysis.

## License
This project is licensed under the Apache License.

