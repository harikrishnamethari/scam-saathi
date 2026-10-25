import re

files_to_check = [
    "frontend/index.html",
    "frontend/static/app.js",
    "frontend/static/style.css",
]

issues = []
for filepath in files_to_check:
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    # Check for Google API key pattern
    if re.search(r"AIza[A-Za-z0-9_-]{35}", content):
        issues.append(filepath + ": Google API key pattern found")
    # Check for GEMINI_API_KEY with actual value
    if re.search(r"GEMINI_API_KEY\s*=\s*[A-Za-z0-9]{10,}", content):
        issues.append(filepath + ": GEMINI_API_KEY with value found")

if issues:
    print("SECURITY ISSUES:")
    for i in issues:
        print(i)
else:
    print("Security check PASSED: No API keys in client-side files")

with open("backend/main.py", "r") as f:
    main_content = f.read()
if "print(req.message)" in main_content:
    print("WARNING: message may be logged")
else:
    print("Privacy check PASSED: No raw message logging")
