import os
import re
import json
from pathlib import Path

def extract_file_based_ground_truth(base_dir, web_subdirs=None, valid_exts=None):
    p = Path(base_dir)
    ground_truth = []
    exclude_dirs = {'.git', '.github', 'tests', 'docker', 'node_modules', 'vendor'}
    
    if valid_exts is None:
        valid_exts = ('.php', '.html', '.css', '.js', '.png', '.jpg', '.gif', '.ico', '.pdf', '.md', '.txt', '.dist', '.json')
        
    start_dirs = [p / d for d in web_subdirs] if web_subdirs else [p]
    
    for s_dir in start_dirs:
        if not s_dir.exists():
            continue
        for root, dirs, files in os.walk(s_dir):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for f in files:
                full_path = Path(root) / f
                rel_path = full_path.relative_to(s_dir).as_posix()
                if f.endswith(valid_exts) or f.startswith('.'):
                    ground_truth.append("/" + rel_path.lstrip('/'))
                    
    return sorted(list(set(ground_truth)))

def extract_express_routes(base_dir):
    p = Path(base_dir)
    routes = set()
    route_patterns = [
        re.compile(r"""(?:app|router)\.(?:get|post|put|delete|patch|use)\s*\(\s*['"`]([^'"`]+)['"`]"""),
        re.compile(r"""(?:api|rest)\s*[:=]\s*['"`]([^'"`]+)['"`]"""),
        re.compile(r"""path\s*:\s*['"`]([^'"`]+)['"`]""")
    ]
    for root, dirs, files in os.walk(p):
        if any(x in root for x in ('node_modules', '.git', 'dist', 'build')):
            continue
        for f in files:
            if f.endswith(('.ts', '.js')):
                try:
                    content = (Path(root) / f).read_text(encoding='utf-8', errors='ignore')
                    for pattern in route_patterns:
                        for match in pattern.findall(content):
                            if match and not match.startswith(('*', 'http', '..')):
                                routes.add("/" + match.lstrip('/'))
                except Exception:
                    pass
    return sorted(list(routes))

def extract_nodegoat_routes(base_dir):
    p = Path(base_dir)
    routes = set()
    # Read routes from app/routes/index.js and app/routes/tutorial.js
    idx = p / "app" / "routes" / "index.js"
    if idx.exists():
        content = idx.read_text(encoding='utf-8', errors='ignore')
        for m in re.findall(r"""app\.(?:get|post|use)\s*\(\s*['"`]([^'"`]+)['"`]""", content):
            routes.add(m)
    tut = p / "app" / "routes" / "tutorial.js"
    if tut.exists():
        content = tut.read_text(encoding='utf-8', errors='ignore')
        pages = ["a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10", "redos", "ssrf"]
        routes.add("/tutorial")
        for pg in pages:
            routes.add(f"/tutorial/{pg}")
    return sorted(list(routes))

def extract_dvga_routes(base_dir):
    p = Path(base_dir)
    routes = set()
    views = p / "core" / "views.py"
    if views.exists():
        content = views.read_text(encoding='utf-8', errors='ignore')
        for m in re.findall(r"""@app\.route\(\s*['"`]([^'"`]+)['"`]""", content):
            routes.add(m)
        for m in re.findall(r"""add_url_rule\(\s*['"`]([^'"`]+)['"`]""", content):
            routes.add(m)
        # Extract GraphQL operations
        query_match = re.search(r"class Query\([^)]+\):(.*?)(?=\nclass|\Z)", content, re.DOTALL)
        if query_match:
            for q in re.findall(r"^\s+([a-zA-Z0-9_]+)\s*=\s*graphene\.", query_match.group(1), re.MULTILINE):
                routes.add(f"/graphql#query:{q}")
        mutation_match = re.search(r"class Mutation\([^)]+\):(.*?)(?=\nclass|\Z)", content, re.DOTALL)
        if mutation_match:
            for mut in re.findall(r"^\s+([a-zA-Z0-9_]+)\s*=\s*", mutation_match.group(1), re.MULTILINE):
                routes.add(f"/graphql#mutation:{mut}")
    return sorted(list(routes))

def extract_vapi_routes(base_dir):
    p = Path(base_dir)
    routes = set()
    postman = p / "postman" / "vAPI.postman_collection.json"
    if postman.exists():
        try:
            with open(postman) as f:
                col = json.load(f)
            def walk(items):
                for it in items:
                    if 'item' in it:
                        walk(it['item'])
                    elif 'request' in it:
                        req = it['request']
                        url = req.get('url', {})
                        raw = url.get('raw', '') if isinstance(url, dict) else str(url)
                        # Normalize http://{{host}}/vapi/api1/user -> /vapi/api1/user
                        m = re.search(r'\{\{host\}\}(/.*)', raw)
                        if m:
                            routes.add(m.group(1))
                        else:
                            routes.add(raw)
            walk(col.get('item', []))
        except Exception:
            pass
    # Also parse vapi/routes/api.php
    api_php = p / "vapi" / "routes" / "api.php"
    if api_php.exists():
        content = api_php.read_text(encoding='utf-8', errors='ignore')
        for m in re.findall(r"""Route::(?:get|post|put|delete|patch)\(\s*['"`]([^'"`]+)['"`]""", content):
            routes.add("/api/" + m.lstrip('/'))
    return sorted(list(routes))

def extract_crapi_routes(base_dir):
    p = Path(base_dir)
    routes = set()
    for root, dirs, files in os.walk(p):
        for f in files:
            if f.endswith(('.yaml', '.yml', '.json')) and any(k in f.lower() for k in ('swagger', 'openapi', 'api')):
                try:
                    content = (Path(root) / f).read_text(encoding='utf-8', errors='ignore')
                    for m in re.findall(r"""^\s{2,4}(/[a-zA-Z0-9_\-\/\{\}]+):\s*$""", content, re.MULTILINE):
                        routes.add(m)
                except Exception:
                    pass
    for root, dirs, files in os.walk(p):
        if any(x in root for x in ('node_modules', '.git')):
            continue
        for f in files:
            if f.endswith(('.py', '.java', '.go', '.js', '.ts')):
                try:
                    content = (Path(root) / f).read_text(encoding='utf-8', errors='ignore')
                    for m in re.findall(r"""['"`](/(?:identity|workshop|community)/api/v[0-9]+/[^'"`\s]+)['"`]""", content):
                        routes.add(m)
                except Exception:
                    pass
    return sorted(list(routes))

def main():
    base = Path("/home/kali/Desktop/DevBackUp-29.10/data/targets_ground_truth")
    
    dvwa_gt = extract_file_based_ground_truth(base / "dvwa")
    bwapp_gt = extract_file_based_ground_truth(base / "bwapp")
    dvna_gt = extract_express_routes(base / "dvna") + extract_file_based_ground_truth(base / "dvna", web_subdirs=['public', 'views'])
    dvna_gt = sorted(list(set(dvna_gt)))
    
    juice_gt = extract_express_routes(base / "juice-shop")
    frontend_routing = base / "juice-shop" / "frontend" / "src" / "app" / "app.routing.ts"
    if frontend_routing.exists():
        try:
            content = frontend_routing.read_text(encoding='utf-8', errors='ignore')
            for match in re.findall(r"""path:\s*['"`]([^'"`]*)['"`]""", content):
                if match:
                    juice_gt.append("/#/" + match)
        except Exception:
            pass
    juice_gt = sorted(list(set(juice_gt)))
    
    crapi_gt = extract_crapi_routes(base / "crapi")

    # Extended apps
    nodegoat_gt = extract_nodegoat_routes(base / "nodegoat")
    dvga_gt = extract_dvga_routes(base / "dvga")
    vapi_gt = extract_vapi_routes(base / "vapi")

    results = {
        "dvwa": {"total": len(dvwa_gt), "routes": dvwa_gt},
        "bwapp": {"total": len(bwapp_gt), "routes": bwapp_gt},
        "dvna": {"total": len(dvna_gt), "routes": dvna_gt},
        "juice_shop": {"total": len(juice_gt), "routes": juice_gt},
        "crapi": {"total": len(crapi_gt), "routes": crapi_gt},
        "nodegoat": {"total": len(nodegoat_gt), "routes": nodegoat_gt},
        "dvga": {"total": len(dvga_gt), "routes": dvga_gt},
        "vapi": {"total": len(vapi_gt), "routes": vapi_gt}
    }
    
    out_file = base / "ground_truth_extended.json"
    with open(out_file, 'w') as f:
        json.dump(results, f, indent=2)
        
    print(f"Ground Truth Extended generated successfully at {out_file}:")
    for app, data in results.items():
        print(f"  - {app:<12}: {data['total']} routes/endpoints")

if __name__ == "__main__":
    main()
