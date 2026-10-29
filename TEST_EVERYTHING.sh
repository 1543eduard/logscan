#!/bin/bash
# Complete test script - run this to verify everything works

echo "======================================"
echo " LOGSCAN - COMPLETE VERIFICATION TEST"
echo "======================================"

# Kill old processes
echo ""
echo "1. Stopping old server..."
pkill -f "app.py" 2>/dev/null || true
sleep 2

# Start server
echo "2. Starting fresh server..."
cd /tmp/opencode/logscan-git
timeout 60 bash bin/logscan &
LOGSCAN_PID=$!
sleep 6

# Get port
PORT=$(lsof -i -P -n 2>/dev/null | grep python | grep LISTEN | awk '{print $9}' | cut -d: -f2 | head -1)

if [ -z "$PORT" ]; then
    echo "❌ ERROR: Server did not start!"
    ps aux | grep app.py
    exit 1
fi

echo "✅ Server started on port $PORT"

# Create test log
echo ""
echo "3. Creating test log file..."
cat > /tmp/test_verify.log << 'EOF'
91.200.123.86 - - [28/Oct/2026:15:10:00 +0000] "GET / HTTP/1.1" 200 4096 "-" "Mozilla/5.0"
91.200.123.87 - - [28/Oct/2026:15:10:01 +0000] "GET /api HTTP/1.1" 200 8192 "-" "curl/7.0"
91.200.123.88 - - [28/Oct/2026:15:10:02 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
91.200.123.89 - - [28/Oct/2026:15:10:03 +0000] "GET /admin HTTP/1.1" 403 256 "-" "Mozilla/5.0"
91.200.123.90 - - [28/Oct/2026:15:10:04 +0000] "GET /shell.php HTTP/1.1" 404 0 "-" "curl/7.0"
EOF
echo "✅ Test log created"

# Test upload
echo ""
echo "4. Testing upload endpoint..."
UPLOAD=$(curl -s -X POST "http://127.0.0.1:$PORT/api/upload" \
  -F "files=@/tmp/test_verify.log")

echo "Upload response: $(echo "$UPLOAD" | wc -c) bytes"

# Extract dataset_id
DATASET_ID=$(echo "$UPLOAD" | python3 -c "import sys, json; print(json.load(sys.stdin).get('dataset_id', ''))" 2>/dev/null)

if [ -z "$DATASET_ID" ]; then
    echo "❌ ERROR: No dataset_id returned from upload!"
    echo "Response: $UPLOAD"
    kill $LOGSCAN_PID 2>/dev/null || true
    exit 1
fi

echo "✅ Upload successful - Dataset ID: $DATASET_ID"

# Test /rezultate with dataset
echo ""
echo "5. Testing /rezultate?id=$DATASET_ID..."

REZULTATE_PAGE=$(curl -s "http://127.0.0.1:$PORT/rezultate?id=$DATASET_ID")

# Check what's in the response
echo "Response size: $(echo "$REZULTATE_PAGE" | wc -c) bytes"

if echo "$REZULTATE_PAGE" | grep -q "DATASET_ID = "; then
    echo "✅ Contains DASHBOARD code"
else
    echo "❌ MISSING DASHBOARD code"
fi

if echo "$REZULTATE_PAGE" | grep -q "_onUploadSuccess"; then
    echo "✅ Contains _onUploadSuccess function"
else
    echo "❌ MISSING _onUploadSuccess function"
fi

if echo "$REZULTATE_PAGE" | grep -q "Auto-load dataset from URL"; then
    echo "✅ Contains auto-load code"
else
    echo "❌ MISSING auto-load code"
fi

if echo "$REZULTATE_PAGE" | grep -q "Încarcă un jurnal"; then
    echo "❌ CONTAINS OLD UPLOAD INTERFACE"
else
    echo "✅ Does NOT contain old upload interface"
fi

echo ""
echo "======================================"
echo " FINAL TEST URL:"
echo "======================================"
echo ""
echo "http://127.0.0.1:$PORT/rezultate?id=$DATASET_ID"
echo ""
echo "Open this in browser and verify:"
echo "  1. You see DASHBOARD (not upload page)"
echo "  2. You see data: Requests, IPs, etc"
echo "  3. You see Workplace + Features on left"
echo ""
echo "Press ENTER to close server..."
read
kill $LOGSCAN_PID 2>/dev/null || true
