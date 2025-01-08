import os
import json
import yaml
import subprocess
import requests
from datetime import datetime
from typing import List, Dict, Optional, Union


class OSINTScraper:
    """
    A class to automate OSINT data collection using tools like theHarvester
    and APIs like Shodan and VirusTotal.
    """

    def __init__(
        self, 
        input_file: str, 
        output_dir: str, 
        shodan_api_key: Optional[str] = None, 
        virustotal_api_key: Optional[str] = None
    ):
        self.input_file = input_file
        self.output_dir = output_dir
        self.shodan_api_key = shodan_api_key
        self.virustotal_api_key = virustotal_api_key
        self.targets = self._load_targets()

    def _load_targets(self) -> List[str]:
        """Load targets from a YAML file."""
        try:
            with open(self.input_file, "r") as file:
                data = yaml.safe_load(file)
                targets = data.get("targets", [])
                if not targets:
                    raise ValueError("No targets found in the input file.")
                return targets
        except FileNotFoundError:
            raise FileNotFoundError(f"Input file '{self.input_file}' not found.")
        except yaml.YAMLError as e:
            raise ValueError(f"Error parsing YAML file: {e}")

    @staticmethod
    def _is_ip(target: str) -> bool:
        """Check if the target is a valid IP address."""
        parts = target.split(".")
        return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

    def _run_command(self, command: List[str]) -> str:
        """Run a command in the terminal and return its output."""
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            return f"Error executing command: {' '.join(command)}\n{e}"

    def _run_theharvester(self, target: str) -> str:
        """Run theHarvester to collect data."""
        print(f"[+] Running theHarvester for {target}...")
        return self._run_command(["theHarvester", "-d", target, "-l", "500", "-b", "all"])

    def _query_shodan(self, ip: str) -> Dict:
        """Query the Shodan API for IP information."""
        if not self.shodan_api_key:
            return {"error": "Shodan API key is missing."}

        print(f"[+] Querying Shodan for IP: {ip}...")
        url = f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_api_key}"
        try:
            response = requests.get(url)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            return {"error": f"Failed to query Shodan: {e}"}

    def _query_virustotal(self, domain: str) -> Dict:
        """Query the VirusTotal API for domain information."""
        if not self.virustotal_api_key:
            return {"error": "VirusTotal API key is missing."}

        print(f"[+] Querying VirusTotal for domain: {domain}...")
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": self.virustotal_api_key}
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            return {"error": f"Failed to query VirusTotal: {e}"}

    def _save_report(self, target: str, report: Dict):
        """Save the collected data to a JSON file."""
        os.makedirs(self.output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = os.path.join(self.output_dir, f"{target}_report_{timestamp}.json")
        try:
            with open(file_path, "w") as file:
                json.dump(report, file, indent=4)
            print(f"[+] Report saved: {file_path}")
        except IOError as e:
            print(f"[-] Failed to save report for {target}: {e}")

    def process_target(self, target: str):
        """Process a single target to gather OSINT data."""
        print(f"[+] Processing target: {target}")
        report = {"target": target, "results": {}}

        # Run theHarvester
        report["results"]["theHarvester"] = self._run_theharvester(target)

        # Query Shodan (only for IP addresses)
        if self._is_ip(target):
            report["results"]["Shodan"] = self._query_shodan(target)
        else:
            report["results"]["Shodan"] = {"info": "Skipped: Target is not an IP address."}

        # Query VirusTotal
        report["results"]["VirusTotal"] = self._query_virustotal(target)

        # Save the report
        self._save_report(target, report)

    def run(self):
        """Run OSINT gathering for all targets."""
        print("[+] Starting OSINT scraper...")
        for target in self.targets:
            try:
                self.process_target(target)
            except Exception as e:
                print(f"[-] Error processing target '{target}': {e}")
        print("[+] OSINT scraping completed.")


def main():
    """
    Main entry point for the OSINT scraper script.
    """
    print("[+] Initializing OSINT Scraper...")

    # Load API keys from environment variables or fallback to default placeholders
    shodan_api_key = os.getenv("SHODAN_API_KEY", "your_shodan_api_key")
    virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY", "your_virustotal_api_key")

    scraper = OSINTScraper(
        input_file="targets.yaml",
        output_dir="osint_reports",
        shodan_api_key=shodan_api_key,
        virustotal_api_key=virustotal_api_key,
    )

    try:
        scraper.run()
    except (FileNotFoundError, ValueError) as e:
        print(f"[-] {e}")


if __name__ == "__main__":
    main()
