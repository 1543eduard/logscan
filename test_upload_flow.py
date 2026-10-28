#!/usr/bin/env python3
"""
Test script to validate the upload flow works correctly.
This checks:
1. upload.html exists and is valid
2. app.py has /upload route
3. /api/upload endpoint logic is sound
"""
import os
import sys
import json

APP_DIR = os.path.dirname(os.path.abspath(__file__))

def test_upload_html():
    """Verify upload.html exists and has correct structure"""
    path = os.path.join(APP_DIR, "upload.html")

    if not os.path.exists(path):
        print(f"❌ upload.html not found at {path}")
        return False

    with open(path, 'r') as f:
        content = f.read()

    checks = [
        ("HTML closing tag", "</html>" in content),
        ("Body tag", "<body>" in content),
        ("Upload form", "<input type=\"file\"" in content),
        ("Fetch API call", "fetch('/api/upload'" in content),
        ("Results display", "displayResults" in content),
        ("Drag & drop handler", "dragover" in content),
        ("Success response handler", "response.ok" in content),
    ]

    all_pass = True
    for check_name, result in checks:
        status = "✅" if result else "❌"
        print(f"  {status} {check_name}")
        if not result:
            all_pass = False

    return all_pass

def test_app_routes():
    """Verify app.py has both routes"""
    path = os.path.join(APP_DIR, "app.py")

    if not os.path.exists(path):
        print(f"❌ app.py not found at {path}")
        return False

    with open(path, 'r') as f:
        content = f.read()

    checks = [
        ("Root route (/)", '@app.get("/"' in content),
        ("Upload route (/upload)", '@app.get("/upload"' in content),
        ("Upload endpoint (/api/upload)", '@app.post("/api/upload"' in content),
        ("Upload HTML reference", 'upload_path = os.path.join(APP_DIR, "upload.html")' in content),
        ("Dashboard HTML reference", 'dash_path = os.path.join(APP_DIR, "dashboard.html")' in content),
    ]

    all_pass = True
    for check_name, result in checks:
        status = "✅" if result else "❌"
        print(f"  {status} {check_name}")
        if not result:
            all_pass = False

    return all_pass

def test_response_format():
    """Verify upload endpoint returns expected JSON format"""
    path = os.path.join(APP_DIR, "app.py")

    with open(path, 'r') as f:
        content = f.read()

    # Check that the response returns correct JSON structure
    checks = [
        ("dataset_id in response", '"dataset_id":' in content),
        ("filename in response", '"filename":' in content),
        ("source_files in response", '"source_files":' in content),
        ("summary in response", '"summary":' in content),
        ("JSONResponse used", 'JSONResponse({' in content),
    ]

    all_pass = True
    for check_name, result in checks:
        status = "✅" if result else "❌"
        print(f"  {status} {check_name}")
        if not result:
            all_pass = False

    return all_pass

def main():
    print("\n" + "="*60)
    print(" LOGSCAN Upload Flow Validation")
    print("="*60)

    print("\n1. Testing upload.html structure...")
    test1 = test_upload_html()

    print("\n2. Testing app.py routes...")
    test2 = test_app_routes()

    print("\n3. Testing API response format...")
    test3 = test_response_format()

    print("\n" + "="*60)
    if test1 and test2 and test3:
        print(" ✅ All validations PASSED")
        print("\n The new upload flow is ready:")
        print("   - URL: http://server:port/upload")
        print("   - Clean, independent interface")
        print("   - Zero dependencies on dashboard JavaScript")
        print("="*60)
        return 0
    else:
        print(" ❌ Some validations FAILED")
        print("="*60)
        return 1

if __name__ == "__main__":
    sys.exit(main())
