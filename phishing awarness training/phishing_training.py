"""
Phishing Awareness Training Module
====================================
An interactive console-based training program to educate users about
phishing attacks, social engineering tactics, and best practices for
staying safe online.

Author: <Your Name>
Project: Cybersecurity Internship - Task 2
"""

import time
import sys
import random


# ----------------------------- Utility Functions ----------------------------- #

def slow_print(text, delay=0.015):
    """Prints text gradually for a more engaging console experience."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def print_header(title):
    """Prints a formatted section header."""
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def pause():
    input("\nPress Enter to continue...")


# ----------------------------- Training Content ----------------------------- #

def introduction():
    print_header("WELCOME TO PHISHING AWARENESS TRAINING")
    slow_print(
        "Phishing is one of the most common cyberattacks used to steal\n"
        "personal information, login credentials, and financial data.\n"
        "This training will teach you how to recognize and avoid phishing\n"
        "attempts, fake websites, and social engineering tactics."
    )
    pause()


def what_is_phishing():
    print_header("MODULE 1: What is Phishing?")
    slow_print(
        "Phishing is a cyberattack where attackers impersonate a trusted\n"
        "entity (bank, company, colleague, etc.) to trick victims into\n"
        "revealing sensitive information or installing malware.\n\n"
        "Common types of phishing:\n"
        "  1. Email Phishing      - Fake emails impersonating trusted sources\n"
        "  2. Spear Phishing      - Targeted attacks on specific individuals\n"
        "  3. Smishing            - Phishing via SMS/text messages\n"
        "  4. Vishing             - Phishing via phone calls\n"
        "  5. Clone Phishing      - Copy of a legitimate email with malicious links\n"
        "  6. Whaling             - Targeting high-profile executives"
    )
    pause()


def recognizing_phishing_emails():
    print_header("MODULE 2: How to Recognize Phishing Emails")
    slow_print(
        "Red flags to look for in suspicious emails:\n\n"
        "  - Generic greetings ('Dear Customer' instead of your name)\n"
        "  - Urgent or threatening language ('Act now or your account "
        "will be closed!')\n"
        "  - Mismatched or suspicious sender email addresses\n"
        "  - Spelling and grammar mistakes\n"
        "  - Suspicious links (hover before clicking to check the real URL)\n"
        "  - Unexpected attachments\n"
        "  - Requests for sensitive info (passwords, OTPs, card numbers)\n"
        "  - Offers that seem too good to be true"
    )
    pause()


def recognizing_fake_websites():
    print_header("MODULE 3: How to Recognize Fake Websites")
    slow_print(
        "Signs that a website may be fake or malicious:\n\n"
        "  - URL misspellings (e.g., 'arnazon.com' instead of 'amazon.com')\n"
        "  - No HTTPS / missing padlock icon in the address bar\n"
        "  - Poor design quality, broken images, or odd formatting\n"
        "  - Pop-ups asking for login credentials\n"
        "  - Domain doesn't match the company's official domain\n"
        "  - No verifiable contact information or privacy policy"
    )
    pause()


def social_engineering_tactics():
    print_header("MODULE 4: Social Engineering Tactics")
    slow_print(
        "Attackers exploit human psychology rather than just technical\n"
        "flaws. Common tactics include:\n\n"
        "  - Authority      : Pretending to be a boss, IT admin, or bank official\n"
        "  - Urgency/Fear   : Creating panic to force quick action\n"
        "  - Curiosity      : Tempting links/attachments ('See who viewed your profile')\n"
        "  - Trust/Familiarity : Impersonating a known contact or coworker\n"
        "  - Reciprocity    : Offering a 'free gift' in exchange for info\n"
        "  - Pretexting     : Creating a fabricated scenario to extract data"
    )
    pause()


def best_practices():
    print_header("MODULE 5: Best Practices to Avoid Phishing")
    slow_print(
        "Tips to protect yourself:\n\n"
        "  1. Verify the sender's email address carefully\n"
        "  2. Never click suspicious links - type URLs manually instead\n"
        "  3. Enable Multi-Factor Authentication (MFA) wherever possible\n"
        "  4. Keep software, browsers, and antivirus tools updated\n"
        "  5. Don't share OTPs, passwords, or PINs with anyone\n"
        "  6. Hover over links to preview the actual destination\n"
        "  7. Report suspicious emails to your IT/security team\n"
        "  8. When in doubt, contact the organization directly via official "
        "channels"
    )
    pause()


def real_world_examples():
    print_header("MODULE 6: Real-World Examples")
    examples = [
        ("Google & Facebook (2013-2015)",
         "Attacker Evaldas Rimasauskas sent fake invoices impersonating a "
         "hardware vendor, tricking both companies into wiring over $100 "
         "million combined."),
        ("Twitter Bitcoin Scam (2020)",
         "Attackers used vishing (voice phishing) to trick Twitter employees "
         "into giving access to internal admin tools, leading to a massive "
         "celebrity account hijack scam."),
        ("COVID-19 Phishing Campaigns (2020-2021)",
         "Attackers sent fake emails from 'WHO' and 'health authorities' "
         "offering vaccine appointments or relief funds to steal personal "
         "data."),
        ("Target Data Breach (2013)",
         "Attackers used a phishing email to compromise a third-party HVAC "
         "vendor, eventually accessing Target's network and stealing 40 "
         "million credit card records."),
    ]
    for name, desc in examples:
        print(f"\n--- {name} ---")
        slow_print(desc)
    pause()


# ----------------------------- Interactive Quiz ----------------------------- #

QUIZ_QUESTIONS = [
    {
        "question": "Which of these is a common red flag in a phishing email?",
        "options": [
            "A) Personalized greeting with your full name",
            "B) Urgent language demanding immediate action",
            "C) Email from a known, verified contact",
            "D) Properly formatted company signature",
        ],
        "answer": "B",
        "explanation": "Urgency is a classic pressure tactic used to "
                        "prevent victims from thinking critically."
    },
    {
        "question": "What should you do before clicking a link in an email?",
        "options": [
            "A) Click immediately if it looks official",
            "B) Forward it to a friend to check",
            "C) Hover over the link to preview the actual URL",
            "D) Reply asking if it's safe",
        ],
        "answer": "C",
        "explanation": "Hovering over a link reveals the real destination "
                        "URL, helping you spot fake or mismatched domains."
    },
    {
        "question": "Which social engineering tactic relies on impersonating "
                     "a boss or authority figure?",
        "options": [
            "A) Reciprocity",
            "B) Authority",
            "C) Curiosity",
            "D) Scarcity",
        ],
        "answer": "B",
        "explanation": "Attackers exploit our tendency to comply with "
                        "perceived authority figures like managers or IT admins."
    },
    {
        "question": "What is 'smishing'?",
        "options": [
            "A) Phishing through social media ads",
            "B) Phishing via SMS/text messages",
            "C) Phishing via phone calls",
            "D) A type of malware",
        ],
        "answer": "B",
        "explanation": "Smishing = SMS + Phishing, attacks delivered via "
                        "text messages."
    },
    {
        "question": "Which is the safest way to verify a suspicious email "
                     "claiming to be from your bank?",
        "options": [
            "A) Reply directly to the email",
            "B) Click the link and log in to check",
            "C) Call the bank using the number on their official website",
            "D) Ignore it and hope it's fake",
        ],
        "answer": "C",
        "explanation": "Always verify through official, independently "
                        "sourced contact channels - never use contact info "
                        "provided in the suspicious message itself."
    },
    {
        "question": "A URL like 'paypa1-secure-login.com' is an example of:",
        "options": [
            "A) A legitimate PayPal subdomain",
            "B) Typosquatting / domain spoofing",
            "C) A secure HTTPS redirect",
            "D) A verified business domain",
        ],
        "answer": "B",
        "explanation": "Replacing letters with similar-looking characters "
                        "(like '1' for 'l') is a classic typosquatting trick."
    },
]


def run_quiz():
    print_header("INTERACTIVE QUIZ: Test Your Knowledge")
    slow_print("Answer the following questions by typing A, B, C, or D.\n")

    questions = QUIZ_QUESTIONS.copy()
    random.shuffle(questions)
    score = 0
    total = len(questions)

    for i, q in enumerate(questions, start=1):
        print(f"\nQ{i}. {q['question']}")
        for option in q["options"]:
            print(f"   {option}")

        answer = input("\nYour answer: ").strip().upper()

        if answer == q["answer"]:
            print("✅ Correct!")
            score += 1
        else:
            print(f"❌ Incorrect. The correct answer is {q['answer']}.")
        print(f"💡 {q['explanation']}")

    print_header("QUIZ RESULTS")
    percentage = (score / total) * 100
    print(f"You scored {score}/{total} ({percentage:.1f}%)")

    if percentage == 100:
        print("🏆 Perfect score! You're a phishing-spotting expert!")
    elif percentage >= 70:
        print("👍 Great job! You have a solid understanding of phishing risks.")
    elif percentage >= 40:
        print("⚠️  Good effort, but review the material to strengthen your "
              "awareness.")
    else:
        print("🚨 Please review the training modules again - phishing "
              "awareness is critical!")


# ----------------------------- Main Menu ----------------------------- #

def main_menu():
    while True:
        print_header("PHISHING AWARENESS TRAINING - MAIN MENU")
        print("1. Introduction")
        print("2. What is Phishing?")
        print("3. How to Recognize Phishing Emails")
        print("4. How to Recognize Fake Websites")
        print("5. Social Engineering Tactics")
        print("6. Best Practices & Tips")
        print("7. Real-World Examples")
        print("8. Take the Interactive Quiz")
        print("9. Run Full Training (All Modules)")
        print("0. Exit")

        choice = input("\nSelect an option (0-9): ").strip()

        if choice == "1":
            introduction()
        elif choice == "2":
            what_is_phishing()
        elif choice == "3":
            recognizing_phishing_emails()
        elif choice == "4":
            recognizing_fake_websites()
        elif choice == "5":
            social_engineering_tactics()
        elif choice == "6":
            best_practices()
        elif choice == "7":
            real_world_examples()
        elif choice == "8":
            run_quiz()
        elif choice == "9":
            introduction()
            what_is_phishing()
            recognizing_phishing_emails()
            recognizing_fake_websites()
            social_engineering_tactics()
            best_practices()
            real_world_examples()
            run_quiz()
        elif choice == "0":
            print("\nThank you for completing the Phishing Awareness "
                  "Training. Stay safe online! 🔒")
            break
        else:
            print("Invalid option. Please select a number between 0 and 9.")


if __name__ == "__main__":
    main_menu()
