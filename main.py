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
    GHOST-EmailSecurity: Real Email Header & Authentication Forensics
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
            recipient = msg.get("To", "Unknown Recipient")
            date = msg.get("Date", "Unknown Date")
            
            findings.append({
                "type": "Email Metadata",
                "subject": subject,
                "from": sender,
                "to": recipient,
                "date": date
            })

            # Check Authentication-Results or Received headers for SPF/DKIM/DMARC clues
            auth_results = msg.get_all("Authentication-Results", [])
            received_headers = msg.get_all("Received", [])
            
            findings.append({
                "type": "Authentication Headers",
                "authentication_results": auth_results if auth_results else ["No explicit Authentication-Results header found"],
                "received_hop_count": len(received_headers)
            })

            # Check for suspicious attachments or links in body
            attachments = []
            for part in msg.walk():
                filename = part.get_filename()
                if filename:
                    attachments.append(filename)
            
            findings.append({
                "type": "Payloads & Attachments",
                "attachments": attachments if attachments else ["No attachments detected"]
            })

    except Exception as e:
        findings.append({"error": f"Failed to parse email file: {str(e)}"})

    return findings

def main():
    banner()
    parser = argparse.ArgumentParser(description="GHOST-EmailSecurity Engine")
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
        "engine": "GHOST-EmailSecurity v3.0-PRO",
        "findings": findings
    }

    with open(args.json, "w") as f:
        json.dump(report, f, indent=4)
    print(f"[+] Email security report saved to: {args.json}")

if __name__ == "__main__":
    main()
