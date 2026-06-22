"""
Secure Coding Review Tool
==========================
A static analysis tool that reviews Python code for common security
vulnerabilities, provides recommendations, and suggests remediation steps.

Author: <Your Name>
Project: Cybersecurity Internship - Task 3
"""

import re
import sys
import os


# ----------------------------- Utility Functions ----------------------------- #

def print_header(title):
    print("\n" + "=" * 65)
    print(f"  {title}")
    print("=" * 65)


def print_section(title):
    print(f"\n--- {title} ---")


# ----------------------------- Vulnerability Rules ----------------------------- #

VULNERABILITY_RULES = [
    {
        "id": "SEC-001",
        "name": "Use of eval()",
        "pattern": r"\beval\s*\(",
        "severity": "CRITICAL",
        "description": "eval() executes arbitrary code and is extremely dangerous.",
        "recommendation": "Avoid eval() entirely. Use ast.literal_eval() for safe "
                          "literal parsing, or redesign the logic.",
        "remediation": "Replace eval(user_input) with ast.literal_eval(user_input) "
                       "for data parsing.",
    },
    {
        "id": "SEC-002",
        "name": "Use of exec()",
        "pattern": r"\bexec\s*\(",
        "severity": "CRITICAL",
        "description": "exec() allows execution of arbitrary Python code.",
        "recommendation": "Remove exec() and replace with safer alternatives.",
        "remediation": "Refactor code to avoid dynamic execution entirely.",
    },
    {
        "id": "SEC-003",
        "name": "Hardcoded Password",
        "pattern": r"(?i)(password|passwd|pwd|secret|api_key)\s*=\s*['\"].+['\"]",
        "severity": "HIGH",
        "description": "Hardcoded credentials in source code are a major security risk.",
        "recommendation": "Store secrets in environment variables or a secrets manager.",
        "remediation": "Use os.environ.get('PASSWORD') or tools like python-dotenv.",
    },
    {
        "id": "SEC-004",
        "name": "SQL Injection Risk",
        "pattern": r"(execute|cursor\.execute)\s*\(\s*[f'\"].*(%s|\+|\.format|f')",
        "severity": "HIGH",
        "description": "String formatting in SQL queries can lead to SQL injection.",
        "recommendation": "Always use parameterized queries or ORM methods.",
        "remediation": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
    },
    {
        "id": "SEC-005",
        "name": "Use of os.system()",
        "pattern": r"\bos\.system\s*\(",
        "severity": "HIGH",
        "description": "os.system() passes commands to the shell and may allow injection.",
        "recommendation": "Use subprocess.run() with a list of arguments instead.",
        "remediation": "subprocess.run(['ls', '-la'], capture_output=True, text=True)",
    },
    {
        "id": "SEC-006",
        "name": "Use of pickle (Deserialization)",
        "pattern": r"\bpickle\.loads?\s*\(",
        "severity": "HIGH",
        "description": "Deserializing untrusted pickle data can execute arbitrary code.",
        "recommendation": "Use JSON or other safe serialization formats.",
        "remediation": "Replace pickle.load() with json.load() for data serialization.",
    },
    {
        "id": "SEC-007",
        "name": "Weak Hashing Algorithm (MD5/SHA1)",
        "pattern": r"hashlib\.(md5|sha1)\s*\(",
        "severity": "MEDIUM",
        "description": "MD5 and SHA1 are cryptographically broken and should not be "
                       "used for security purposes.",
        "recommendation": "Use SHA-256 or stronger hashing algorithms.",
        "remediation": "hashlib.sha256(data).hexdigest()",
    },
    {
        "id": "SEC-008",
        "name": "Insecure Random Number Generation",
        "pattern": r"\brandom\.(random|randint|choice|randrange)\s*\(",
        "severity": "MEDIUM",
        "description": "The random module is not cryptographically secure.",
        "recommendation": "Use the secrets module for security-sensitive randomness.",
        "remediation": "import secrets; secrets.token_hex(16)",
    },
    {
        "id": "SEC-009",
        "name": "Debug Mode Enabled",
        "pattern": r"(?i)(debug\s*=\s*True|app\.run\s*\(.*debug\s*=\s*True)",
        "severity": "MEDIUM",
        "description": "Debug mode exposes sensitive information and should not be "
                       "enabled in production.",
        "recommendation": "Disable debug mode in production environments.",
        "remediation": "Set DEBUG = False or use environment variables to control it.",
    },
    {
        "id": "SEC-010",
        "name": "Use of assert for Security Checks",
        "pattern": r"\bassert\b.*(auth|login|permission|admin|role)",
        "severity": "MEDIUM",
        "description": "assert statements are removed when Python runs in optimized "
                       "mode (-O), bypassing security checks.",
        "recommendation": "Use explicit if/raise statements for security-critical checks.",
        "remediation": "if not is_admin(user): raise PermissionError('Access denied')",
    },
    {
        "id": "SEC-011",
        "name": "Broad Exception Handling",
        "pattern": r"except\s*:",
        "severity": "LOW",
        "description": "Catching all exceptions can hide security errors and bugs.",
        "recommendation": "Catch specific exceptions and log errors properly.",
        "remediation": "except ValueError as e: logger.error(f'Error: {e}')",
    },
    {
        "id": "SEC-012",
        "name": "Use of shell=True in subprocess",
        "pattern": r"subprocess\.(run|call|Popen).*shell\s*=\s*True",
        "severity": "HIGH",
        "description": "shell=True passes the command to the shell, enabling injection.",
        "recommendation": "Pass commands as a list and avoid shell=True.",
        "remediation": "subprocess.run(['command', 'arg1'], shell=False)",
    },
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_ICONS = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH":     "🟠 HIGH",
    "MEDIUM":   "🟡 MEDIUM",
    "LOW":      "🟢 LOW",
}


# ----------------------------- Core Scanner ----------------------------- #

def scan_code(code_lines):
    """Scans lines of code and returns a list of findings."""
    findings = []
    for line_num, line in enumerate(code_lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue  # skip comment lines
        for rule in VULNERABILITY_RULES:
            if re.search(rule["pattern"], line):
                findings.append({
                    "line": line_num,
                    "code": line.rstrip(),
                    **rule,
                })
    # Sort by severity
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    return findings


def display_findings(findings, source_name="Code"):
    """Displays scan findings in a formatted report."""
    print_header(f"SECURITY SCAN REPORT: {source_name}")

    if not findings:
        print("\n✅ No vulnerabilities detected! The code looks clean.")
        return

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print(f"\nTotal Issues Found: {len(findings)}")
    print(f"  🔴 Critical : {counts['CRITICAL']}")
    print(f"  🟠 High     : {counts['HIGH']}")
    print(f"  🟡 Medium   : {counts['MEDIUM']}")
    print(f"  🟢 Low      : {counts['LOW']}")

    print_section("DETAILED FINDINGS")
    for i, f in enumerate(findings, start=1):
        print(f"\n[{i}] {SEVERITY_ICONS[f['severity']]} | {f['id']} - {f['name']}")
        print(f"    Line {f['line']}: {f['code']}")
        print(f"    Issue      : {f['description']}")
        print(f"    Fix        : {f['recommendation']}")
        print(f"    Example    : {f['remediation']}")

    print_section("REMEDIATION SUMMARY")
    for i, f in enumerate(findings, start=1):
        print(f"  [{i}] Line {f['line']} ({f['id']}): {f['recommendation']}")


def security_score(findings):
    """Calculates a security score out of 100."""
    deductions = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
    total = sum(deductions.get(f["severity"], 0) for f in findings)
    score = max(0, 100 - total)
    return score


def display_score(score):
    print_section("SECURITY SCORE")
    bar = "█" * (score // 5) + "░" * (20 - score // 5)
    print(f"  Score: {score}/100  [{bar}]")
    if score == 100:
        print("  🏆 Excellent! No issues found.")
    elif score >= 75:
        print("  👍 Good security posture, but review flagged issues.")
    elif score >= 50:
        print("  ⚠️  Moderate risk. Address HIGH and CRITICAL issues first.")
    else:
        print("  🚨 High risk! Immediate remediation required.")


# ----------------------------- Demo Vulnerable Code ----------------------------- #

DEMO_VULNERABLE_CODE = '''
import os
import pickle
import random
import hashlib

password = "admin123"
api_key = "sk-abcdef1234567890"

def login(user_input):
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    cursor.execute(query)

def run_command(cmd):
    os.system(cmd)

def hash_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()

def generate_token():
    return random.randint(100000, 999999)

def load_data(data):
    return pickle.loads(data)

def evaluate(expr):
    return eval(expr)

try:
    risky_operation()
except:
    pass

DEBUG = True
'''


# ----------------------------- Secure Code Practices ----------------------------- #

BEST_PRACTICES = [
    ("Input Validation",
     "Always validate and sanitize user inputs before processing."),
    ("Parameterized Queries",
     "Use prepared statements to prevent SQL injection."),
    ("Secrets Management",
     "Never hardcode credentials. Use environment variables or vaults."),
    ("Least Privilege",
     "Run applications with the minimum permissions necessary."),
    ("Dependency Scanning",
     "Regularly audit third-party libraries for known CVEs (use pip-audit)."),
    ("Logging & Monitoring",
     "Log security events but never log sensitive data like passwords."),
    ("Error Handling",
     "Catch specific exceptions. Don't expose stack traces to users."),
    ("Cryptography",
     "Use strong algorithms: SHA-256+, AES-256, bcrypt for passwords."),
    ("Code Reviews",
     "Conduct peer code reviews with a security checklist."),
    ("Keep Dependencies Updated",
     "Regularly update libraries to patch known vulnerabilities."),
]


def show_best_practices():
    print_header("SECURE CODING BEST PRACTICES")
    for i, (title, desc) in enumerate(BEST_PRACTICES, start=1):
        print(f"\n  {i:02}. {title}")
        print(f"      {desc}")


# ----------------------------- File Scanner ----------------------------- #

def scan_file(filepath):
    """Scans a Python file for vulnerabilities."""
    if not os.path.exists(filepath):
        print(f"\n❌ File not found: {filepath}")
        return
    if not filepath.endswith(".py"):
        print("\n⚠️  Warning: This tool is optimized for Python files.")

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    findings = scan_code(lines)
    display_findings(findings, source_name=os.path.basename(filepath))
    score = security_score(findings)
    display_score(score)


# ----------------------------- Main Menu ----------------------------- #

def main_menu():
    while True:
        print_header("SECURE CODING REVIEW TOOL - MAIN MENU")
        print("  1. Scan Demo Vulnerable Code (built-in example)")
        print("  2. Scan a Python File (enter file path)")
        print("  3. View Secure Coding Best Practices")
        print("  4. View All Vulnerability Rules")
        print("  0. Exit")

        choice = input("\nSelect an option (0-4): ").strip()

        if choice == "1":
            print_header("SCANNING DEMO VULNERABLE CODE")
            print("\n[Demo code loaded with intentional vulnerabilities]\n")
            lines = DEMO_VULNERABLE_CODE.splitlines(keepends=True)
            findings = scan_code(lines)
            display_findings(findings, source_name="demo_vulnerable.py")
            score = security_score(findings)
            display_score(score)
            input("\nPress Enter to continue...")

        elif choice == "2":
            filepath = input("\nEnter full path to Python file: ").strip().strip('"')
            scan_file(filepath)
            input("\nPress Enter to continue...")

        elif choice == "3":
            show_best_practices()
            input("\nPress Enter to continue...")

        elif choice == "4":
            print_header("ALL VULNERABILITY RULES")
            for rule in VULNERABILITY_RULES:
                print(f"\n  [{rule['id']}] {SEVERITY_ICONS[rule['severity']]} - "
                      f"{rule['name']}")
                print(f"    {rule['description']}")
            input("\nPress Enter to continue...")

        elif choice == "0":
            print("\nThank you for using the Secure Coding Review Tool. "
                  "Write safe code! 🔐")
            break
        else:
            print("  Invalid option. Please select 0-4.")


if __name__ == "__main__":
    main_menu()