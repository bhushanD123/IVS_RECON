# Security Assessment Tool

A web-based reconnaissance tool designed for CTF players and bug bounty hunters to automate target information gathering. This tool provides a clean interface for scanning targets and analyzing their security posture.

## Features

- Port scanning with service detection
- Vulnerability assessment
- CVE detection and analysis
- Metasploit exploit suggestions
- Web application vulnerability scanning
- Downloadable scan reports
- Modern, responsive UI

## Prerequisites

- Python 3.7+
- Nmap
- SQLite3

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd security-assessment-tool
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required packages:
```bash
pip install -r requirements.txt
```

## Usage

1. Start the application:
```bash
python app.py
```

2. Open your web browser and navigate to:
```
http://localhost:5000
```

3. Enter a target IP address and click "Scan" to begin the assessment.

## Security Considerations

- This tool should only be used against systems you have explicit permission to test
- Some features require root/administrator privileges
- Always follow responsible disclosure practices
- Do not use against production systems without proper authorization

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems. 