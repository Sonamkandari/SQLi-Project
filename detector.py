import re
import time

# Simple SQLi signatures (expand as needed)
SIGS = [
    r"(?i)\bOR\b\s+'?1'?='?1",
    r"(?i)\bUNION\b",
    r"(?i)\bSELECT\b.*\bFROM\b",
    r"(?i)\bSLEEP\(",
    r"(?i)--",            # comment
    r"(?i);",             # statement terminator
    r"(?i)\/\*.*\*\/",    # C-style comment
    r"(?i)'\s*or\s*'1'='1",
    r"(?i)xp_cmdshell",
]

sig_compiled = [re.compile(s) for s in SIGS]

def is_sqli(payload):
    """Return (True, matched_pattern) if suspicious."""
    for r in sig_compiled:
        if r.search(payload):
            return True, r.pattern
    return False, None

def sanitize(payload):
    """Basic sanitizer — escapes single quotes (demo only)."""
    # Note: real prevention relies on parameterized queries; this is just an illustration.
    return payload.replace("'", "''")

def log_detection(payload, pattern, remote="local"):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    with open("detections.log", "a") as f:
        f.write(f"{ts}\t{remote}\t{pattern}\t{payload}\n")
