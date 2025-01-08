# **OSINT Scraper Documentation**

## **Overview**
The `osint_scraper.py` is an automated Open-Source Intelligence (OSINT) gathering tool designed to streamline the process of collecting intelligence on domains and IPs. It leverages tools like `theHarvester` and APIs such as **Shodan** and **VirusTotal** to provide consolidated reports. The tool is designed for cybersecurity professionals, penetration testers, and researchers, offering a modular, extensible, and error-resilient framework.

---

## **Features**

### **Key Functionalities**
1. **Multi-Tool Integration**:
   - **theHarvester**: Gathers public intelligence from search engines and other sources.
   - **Shodan API**: Retrieves detailed information about IPs, including open ports and vulnerabilities.
   - **VirusTotal API**: Analyzes domains for malware, reputation, and threat intelligence.

2. **Target Handling**:
   - Supports both domains and IPs.
   - Dynamically selects appropriate tools based on the target type.

3. **Reporting**:
   - Generates detailed JSON reports for each target.
   - Organizes reports in a timestamped, structured format.

4. **Error Handling**:
   - Robust handling of invalid inputs, network issues, and API errors.
   - Provides detailed error logs to assist troubleshooting.

5. **Extensibility**:
   - Modular design enables easy addition of new OSINT tools or APIs.

---

## **Setup Instructions**

### **Dependencies**
1. **Install Required Python Libraries**:
   ```bash
   pip install pyyaml requests
   ```
2. **Install theHarvester**:
   ```bash
   sudo apt update && sudo apt install theharvester
   ```

### **API Keys**
Obtain API keys for:
- **Shodan**: [Get an API Key](https://account.shodan.io/)
- **VirusTotal**: [Get an API Key](https://www.virustotal.com/)

Set them as environment variables for secure access:
```bash
export SHODAN_API_KEY="your_shodan_api_key"
export VIRUSTOTAL_API_KEY="your_virustotal_api_key"
```

### **Input File**
Prepare a YAML file named `targets.yaml` containing your targets:
```yaml
targets:
  - example.com
  - 8.8.8.8
  - 1.1.1.1
```

---

## **Usage**

### **Running the Script**
Execute the script:
```bash
python3 osint_scraper.py
```

### **Generated Reports**
- Reports are saved in the `osint_reports` directory.
- Each target has a unique JSON report named with the target and a timestamp.

---

## **Detailed Workflow**

### **1. Input File Parsing**
- The script reads `targets.yaml`, validating its structure and ensuring targets are correctly formatted.

### **2. OSINT Gathering**
- **Domains**:
  - Data is collected using `theHarvester` and the VirusTotal API.
- **IPs**:
  - Data is collected using `theHarvester`, Shodan, and the VirusTotal API.

### **3. Report Generation**
- All results are consolidated into a JSON file for each target.
- The reports are timestamped to ensure no overwrites and to provide traceability.

---

## **Key Components**

### **OSINTScraper Class**
Encapsulates all functionality:
- **Initialization**: Reads input, validates targets, and sets up configurations.
- **Processing**:
  - Runs `theHarvester` for both domains and IPs.
  - Queries Shodan for IPs.
  - Queries VirusTotal for domains and IPs.
- **Reporting**:
  - Saves structured JSON reports in the `osint_reports` directory.

### **Main Methods**
1. **`_load_targets()`**:
   - Reads targets from the input YAML file and validates them.
2. **`_run_theharvester(target)`**:
   - Executes `theHarvester` and captures its output.
3. **`_query_shodan(ip)`**:
   - Fetches data from the Shodan API for IPs.
4. **`_query_virustotal(domain)`**:
   - Fetches data from the VirusTotal API for domains.
5. **`_save_report(target, report)`**:
   - Saves collected data into a structured JSON file.
6. **`_is_ip(target)`**:
   - Determines if a target is an IP address.

---

## **Error Handling**

### **File-Related Errors**
- Missing `targets.yaml` file or invalid YAML structure.
- Solution: Ensure the file exists and is properly formatted.

### **API Errors**
- Missing or invalid API keys.
- Rate limits exceeded.
- Solution: Verify API keys and monitor usage.

### **Command Errors**
- Errors while running `theHarvester`.
- Solution: Ensure `theHarvester` is installed and properly configured.

---

## **Extensibility**

### **Adding New Tools or APIs**
1. **Define a New Method**:
   - Create a method in the `OSINTScraper` class to handle the tool or API.
   ```python
   def _query_new_tool(self, target: str) -> Dict:
       # Query logic for the new tool
       return {}
   ```

2. **Integrate with `process_target()`**:
   - Add the method call to the target processing workflow:
   ```python
   report["results"]["NewTool"] = self._query_new_tool(target)
   ```

---

## **Sample Output**

### **Example Report**
For the target `example.com`:
```json
{
  "target": "example.com",
  "results": {
    "theHarvester": "Collected data from search engines...",
    "Shodan": {"info": "Skipped: Target is not an IP address."},
    "VirusTotal": {
      "reputation": 5,
      "categories": ["malware", "phishing"]
    }
  }
}
```

---

## **Best Practices**

1. **API Key Management**:
   - Use environment variables to manage sensitive information securely.

2. **Validate Input**:
   - Ensure all targets in `targets.yaml` are properly formatted.

3. **Monitor API Usage**:
   - Be aware of rate limits for Shodan and VirusTotal APIs.

4. **Review Reports**:
   - Analyze the JSON reports carefully for actionable insights.

---

## **Known Limitations**

1. **Sequential Processing**:
   - Targets are processed one at a time, which may increase runtime for large datasets.
   - Potential Improvement: Implement parallel processing using threading or multiprocessing.

2. **API Rate Limits**:
   - Limited requests for free-tier accounts on Shodan and VirusTotal.
   - Solution: Upgrade to higher-tier API plans for more queries.

3. **Tool Dependencies**:
   - Relies on `theHarvester`, which must be installed and accessible in the system's PATH.

---

## **Future Enhancements**

1. **Parallel Processing**:
   - Use multithreading or multiprocessing to process multiple targets concurrently.

2. **Additional Tools**:
   - Integrate tools like `Amass`, `Sublist3r`, or custom recon scripts.

3. **Web-Based Dashboard**:
   - Develop a web interface for easier configuration and real-time report viewing.

4. **Custom Output Formats**:
   - Support additional formats like CSV or HTML for better report consumption.

---

## **Support**

For any issues, feature requests, or suggestions:
- Contact: **youremail@example.com**
- GitHub Repository: [GitHub Link] (Add your repository link here)

---

## **Conclusion**

The `osint_scraper.py` is a versatile, modular tool for automating OSINT gathering. Its extensibility and focus on modularity make it a reliable choice for professionals and researchers in the cybersecurity field. With its structured outputs and robust error handling, the tool simplifies and accelerates intelligence gathering.
