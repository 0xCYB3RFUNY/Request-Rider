import requests
import json
import time

def login_dvwa():
    s = requests.Session()
    # 1. Fetch login.php to get user_token (CSRF)
    r = s.get("http://127.0.0.1:8088/login.php")
    import re
    token_match = re.search(r"name='user_token'\s+value='([^']+)'", r.text)
    user_token = token_match.group(1) if token_match else ""
    
    # 2. Post login credentials (admin/password)
    login_data = {
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": user_token
    }
    r2 = s.post("http://127.0.0.1:8088/login.php", data=login_data, allow_redirects=False)
    
    # 3. Set security level to low
    s.get("http://127.0.0.1:8088/security.php")
    s.post("http://127.0.0.1:8088/security.php", data={"security": "low", "seclev_submit": "Submit"})
    
    cookies = []
    for k, v in s.cookies.items():
        cookies.append(f"{k}={v}")
    cookie_str = "; ".join(cookies)
    print(f"[DVWA] Logged in! Cookies: {cookie_str}")
    return cookie_str

def main():
    cookie_str = login_dvwa()
    
    # Test Static Crawler with Cookies via engine /proxy/target-map
    print("\n[DVWA] Starting Static Crawl with Session Cookie via Go Engine...")
    payload = {
        "url": "http://127.0.0.1:8088/",
        "max_pages": 150,
        "max_depth": 3,
        "same_origin": True,
        "cookies": cookie_str
    }
    r = requests.post("http://127.0.0.1:8000/api/target-map", json=payload)
    data = r.json()
    map_id = data.get("map_id")
    print(f"[DVWA] Crawl started, map_id: {map_id}")
    
    # Poll status
    for _ in range(40):
        time.sleep(1)
        r_poll = requests.get(f"http://127.0.0.1:8000/api/target-map/{map_id}")
        p_data = r_poll.json()
        status = p_data.get("status")
        pages = p_data.get("pages", [])
        if status in ("completed", "cancelled", "failed"):
            print(f"[DVWA] Crawl finished with status: {status}, pages: {len(pages)}")
            break
            
    # Check if vulnerabilities/* were discovered!
    vuln_pages = [p.get("url") for p in pages if "/vulnerabilities/" in p.get("url", "")]
    print(f"[DVWA] Vulnerabilities endpoints discovered: {len(vuln_pages)}")
    for vp in vuln_pages[:15]:
        print(f"   -> {vp}")

if __name__ == "__main__":
    main()
