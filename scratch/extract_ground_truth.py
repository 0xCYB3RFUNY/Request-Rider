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

def extract_crapi_routes(base_dir):
    p = Path(base_dir)
    routes = set()
    # Search for OpenAPI/Swagger files
    for root, dirs, files in os.walk(p):
        for f in files:
            if f.endswith(('.yaml', '.yml', '.json')) and any(k in f.lower() for k in ('swagger', 'openapi', 'api')):
                try:
                    content = (Path(root) / f).read_text(encoding='utf-8', errors='ignore')
                    # Look for paths: /identity/api/v2/...
                    for m in re.findall(r"""^\s{2,4}(/[a-zA-Z0-9_\-\/\{\}]+):\s*$""", content, re.MULTILINE):
                        routes.add(m)
                except Exception:
                    pass
    # Also inspect controllers in services/
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
    # Add frontend Angular routes
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
    
    out = {
        "dvwa": {"total": len(dvwa_gt), "endpoints": dvwa_gt},
        "bwapp": {"total": len(bwapp_gt), "endpoints": bwapp_gt},
        "dvna": {"total": len(dvna_gt), "endpoints": dvna_gt},
        "juice_shop": {"total": len(juice_gt), "endpoints": juice_gt},
        "crapi": {"total": len(crapi_gt), "endpoints": crapi_gt}
    }
    
    out_file = base / "ground_truth_multi.json"
    with open(out_file, "w") as f:
        json.dump(out, f, indent=2)
        
    print("=== MULTI-TARGET GROUND TRUTH SUMMARY ===")
    for k, v in out.items():
        print(f"Target: {k:12} | Total Endpoints: {v['total']}")
        print(f"   Sample: {v['endpoints'][:4]}")

if __name__ == "__main__":
    main()
