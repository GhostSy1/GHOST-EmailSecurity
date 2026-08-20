import os
import sys
import argparse
import json
import email
from email import policy

def banner():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')
    print(r"""
  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗     ███████╗███████╗ ██████╗██╗   ██╗
 ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝     ██╔════╝██╔════╝██╔════╝██║   ██║
 ██║  ███╗███████║██║   ██║███████╗   ██║        ███████╗████ôt  ██║     ██║   ██║
 ██║   ██║██╔══██║██║   ██║╚════██║   ██║        ╚════██║██╔════╝██║     ██║   ██║
 ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║        ███████║███████╗╚██████╗╚██████╔╝
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝        ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ 
    GHOST-EmailSecurity: Advanced SPF, DKIM & DMARC Alignment Forensics (v3.2-PRO)
""")

def analyze_email_file(eml_path):
    findings = []
    if not os.path.exists(eml_path):
        return [{"error": f"Email file not found: {eml_path}"}]

    try:
        with open(eml_path, "r", encoding="utf-8", errors="ignore") as f:
            msg = email.message_from_file(f, policy=policy.default)
            
            subject = msg.get("Subject", "No Subject")
            sender = msg.get("From", "Unknown Sender")
            return_path = msg.get("Return-Path", "Unknown Return-Path")
            recipient = msg.get("To", "Unknown Recipient")
            
            findings.append({
                "type": "Header Alignment Overview",
                "subject": subject,
                "from_header": sender,
                "return_path": return_path
            })

            # Check SPF, DKIM, DMARC via Authentication-Results
            auth_results = msg.get_all("Authentication-Results", [])
            spf_pass = any("spf=pass" in r.lower() for r in auth_results)
            dkim_pass = any("dkim=pass" in r.lower() for r in auth_results)
            dmarc_pass = any("dmarc=pass" in r.lower() for r in auth_results)

            findings.append({
                "type": "Authentication & Policy Check",
                "spf_status": "PASS" if spf_pass else "FAIL / UNKNOWN",
                "dkim_status": "PASS" if dkim_pass else "FAIL / UNKNOWN",
                "dmarc_status": "PASS" if dmarc_pass else "FAIL / UNKNOWN",
                "raw_authentication_results": auth_results if auth_results else ["None found"]
            })

            # Check for spoofing / domain mismatch
            domain_mismatch = False
            if "@" in sender and "@" in return_path:
                from_domain = sender.split("@")[-1].strip(">").lower()
                return_domain = return_path.split("@")[-1].strip(">").lower()
                if from_domain != return_domain:
                    domain_mismatch = True

            findings.append({
                "type": "Domain Alignment Analysis",
                "from_domain": sender,
                "return_path_domain": return_path,
                "domain_mismatch_detected": domain_mismatch,
                "spoofing_risk": "HIGH" if domain_mismatch and not dmarc_pass else "LOW"
            })

    except Exception as e:
        findings.append({"error": f"Failed to parse email: {str(e)}"})

    return findings

def main():
    banner()
    parser = argparse.ArgumentParser(description="GHOST-EmailSecurity Enterprise Engine")
    parser.add_argument("--target", help="Path to raw email (.eml) file")
    parser.add_argument("--json", help="Output JSON report path", default="email_report.json")
    args, unknown = parser.parse_known_args()

    target = args.target
    if not target:
        target = input("[*] Enter path to raw email (.eml) file: ").strip()

    print(f"\n[+] Analyzing email file: {target}")
    findings = analyze_email_file(target)

    report = {
        "email_file": target,
        "engine": "GHOST-EmailSecurity v3.2-PRO",
        "findings": findings
    }

    with open(args.json, "w") as f:
        json.dump(report, f, indent=4)
    print(f"[+] Email security report saved to: {args.json}")

if __name__ == "__main__":
    main()
