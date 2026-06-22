# 🔐 Secure Coding Review Tool

A Python-based static analysis tool that scans code for common security vulnerabilities, provides recommendations, and suggests remediation steps.

**Project:** Cybersecurity Internship - Task 3
**Language:** Python 3.x
**Method:** Manual Inspection + Static Analysis (Regex-based)

---

## 📋 Features

- ✅ Scans Python code for **12 vulnerability types**
- ✅ Classifies issues by severity: **Critical / High / Medium / Low**
- ✅ Provides **remediation steps** and fix examples for each issue
- ✅ Calculates a **Security Score (0–100)**
- ✅ Includes a **built-in demo** with intentional vulnerabilities
- ✅ Can scan **any Python file** from your system
- ✅ Lists **10 Secure Coding Best Practices**

---

## 🚨 Vulnerabilities Detected

| ID | Vulnerability | Severity |
|---|---|---|
| SEC-001 | Use of `eval()` | 🔴 Critical |
| SEC-002 | Use of `exec()` | 🔴 Critical |
| SEC-003 | Hardcoded Passwords / API Keys | 🟠 High |
| SEC-004 | SQL Injection Risk | 🟠 High |
| SEC-005 | Use of `os.system()` | 🟠 High |
| SEC-006 | Insecure Deserialization (`pickle`) | 🟠 High |
| SEC-007 | Weak Hashing (MD5 / SHA1) | 🟡 Medium |
| SEC-008 | Insecure Random Number Generation | 🟡 Medium |
| SEC-009 | Debug Mode Enabled | 🟡 Medium |
| SEC-010 | `assert` used for Security Checks | 🟡 Medium |
| SEC-011 | Broad Exception Handling | 🟢 Low |
| SEC-012 | `subprocess` with `shell=True` | 🟠 High |

---

## 🚀 How to Run

**Requirements:** Python 3.x (no external libraries needed)

```bash
python secure_code_review.py
```

### Menu Options

```
1. Scan Demo Vulnerable Code   → See the tool in action instantly
2. Scan a Python File          → Enter any .py file path to audit
3. View Best Practices         → 10 secure coding guidelines
4. View All Vulnerability Rules → Full list of detection rules
0. Exit
```

---

## 📊 Sample Output

```
==================================================================
  SECURITY SCAN REPORT: demo_vulnerable.py
==================================================================

Total Issues Found: 9
  🔴 Critical : 2
  🟠 High     : 4
  🟡 Medium   : 2
  🟢 Low      : 1

[1] 🔴 CRITICAL | SEC-001 - Use of eval()
    Line 35: return eval(expr)
    Issue  : eval() executes arbitrary code and is extremely dangerous.
    Fix    : Use ast.literal_eval() for safe literal parsing.
    Example: Replace eval(user_input) with ast.literal_eval(user_input)

--- SECURITY SCORE ---
  Score: 22/100  [████░░░░░░░░░░░░░░░░]
  🚨 High risk! Immediate remediation required.
```

---

## 🛡️ Secure Coding Best Practices Covered

1. Input Validation
2. Parameterized Queries
3. Secrets Management
4. Least Privilege
5. Dependency Scanning
6. Logging & Monitoring
7. Error Handling
8. Cryptography
9. Code Reviews
10. Keep Dependencies Updated

---

## 📁 Project Structure

```
secure coding review/
│
├── secure_code_review.py   # Main tool
└── README.md               # Documentation
```

---

## 👤 Author

**Name:** Karthikeyan
**Internship:** CodeAlpha Cybersecurity Internship
**Task:** Task 3 - Secure Coding Review
