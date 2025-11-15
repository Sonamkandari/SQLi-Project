import requests
import time

VULN_URL = "http://127.0.0.1:5001/search_vuln"
SECURE_URL = "http://127.0.0.1:5002/search_secure"

def send(url, payload):
    r = requests.post(url, data={'username': payload}, timeout=5)
    return r.text

def main():
    with open('payloads.txt') as f:
        payloads = [line.strip() for line in f if line.strip()]
    results = []
    for p in payloads:
        print("="*60)
        print("Payload:", p)
        try:
            vuln_resp = send(VULN_URL, p)
            secure_resp = send(SECURE_URL, p)
        except Exception as e:
            print("Error contacting app:", e)
            continue

        vuln_vulnerable = ("VULNERABLE" in vuln_resp) and ("No results" not in vuln_resp)
        secure_blocked = ("BLOCKED" in secure_resp) or ("SECURE (BLOCKED)" in secure_resp)
        print("Vulnerable app response snippet:", vuln_resp[:200].replace("\n"," "))
        print("Secure app response snippet:", secure_resp[:200].replace("\n"," "))
        print(f"Interpreted: vulnerable returned results = {vuln_vulnerable}, secure blocked = {secure_blocked}")
        results.append((p, vuln_vulnerable, secure_blocked))
        time.sleep(0.2)
    print("\nSUMMARY")
    for r in results:
        p, vuln_ok, blocked = r
        print(f"{p:40} | vuln returned data: {vuln_ok} | secure blocked: {blocked}")

if __name__ == '__main__':
    main()
