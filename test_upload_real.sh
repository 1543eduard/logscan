#!/bin/bash
# Test upload endpoint with real file

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo " LOGSCAN Upload Test"
echo "=========================================="

# Step 1: Find port
echo ""
echo -e "${YELLOW}Step 1: Finding server port...${NC}"
PORT=$(lsof -i -P -n 2>/dev/null | grep python | grep LISTEN | awk '{print $9}' | cut -d: -f2 | head -1)

if [ -z "$PORT" ]; then
    echo -e "${RED}❌ Server not running${NC}"
    echo "Start with: logscan"
    exit 1
fi

echo -e "${GREEN}✅ Server found on port $PORT${NC}"

# Step 2: Create test file
echo ""
echo -e "${YELLOW}Step 2: Creating test log file...${NC}"
TEST_FILE="/tmp/test_upload_$(date +%s).log"
cat > "$TEST_FILE" << 'EOF'
91.200.123.86 - - [28/Oct/2026:15:10:00 +0000] "GET / HTTP/1.1" 200 4096 "-" "Mozilla/5.0"
91.200.123.86 - - [28/Oct/2026:15:10:01 +0000] "GET /api/users HTTP/1.1" 200 8192 "-" "Mozilla/5.0"
91.200.123.87 - - [28/Oct/2026:15:10:02 +0000] "GET /admin HTTP/1.1" 401 0 "-" "curl/7.0"
91.200.123.88 - - [28/Oct/2026:15:10:03 +0000] "POST /login HTTP/1.1" 401 256 "-" "Mozilla/5.0"
91.200.123.89 - - [28/Oct/2026:15:10:04 +0000] "GET /passwd HTTP/1.1" 404 512 "-" "curl/7.0"
91.200.123.86 - - [28/Oct/2026:15:10:05 +0000] "GET /index.php HTTP/1.1" 200 2048 "-" "Mozilla/5.0"
91.200.123.87 - - [28/Oct/2026:15:10:06 +0000] "GET /../../../etc/passwd HTTP/1.1" 400 0 "-" "curl/7.0"
91.200.123.90 - - [28/Oct/2026:15:10:07 +0000] "POST /api/login HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
91.200.123.91 - - [28/Oct/2026:15:10:08 +0000] "GET /shell.php HTTP/1.1" 404 0 "-" "curl/7.0"
91.200.123.86 - - [28/Oct/2026:15:10:09 +0000] "GET / HTTP/1.1" 200 4096 "-" "Mozilla/5.0"
EOF

echo -e "${GREEN}✅ Test file created: $TEST_FILE${NC}"
echo "   Size: $(wc -c < $TEST_FILE) bytes"

# Step 3: Test HTTP endpoint
echo ""
echo -e "${YELLOW}Step 3: Testing /upload page...${NC}"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT/upload")
if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}✅ /upload page accessible${NC}"
else
    echo -e "${RED}❌ /upload page returned $HTTP_CODE${NC}"
fi

# Step 4: Test API upload
echo ""
echo -e "${YELLOW}Step 4: Testing /api/upload endpoint (5s timeout)...${NC}"
START=$(date +%s%N)

RESPONSE=$(curl -s --max-time 5 -X POST "http://127.0.0.1:$PORT/api/upload" \
  -F "files=@$TEST_FILE" 2>&1)

END=$(date +%s%N)
DURATION=$(( (END - START) / 1000000 ))

if [ $? -eq 0 ]; then
    # Check if response is valid JSON
    if echo "$RESPONSE" | python3 -m json.tool > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Upload successful (${DURATION}ms)${NC}"
        echo ""
        echo "Response:"
        echo "$RESPONSE" | python3 -m json.tool | head -30

        # Extract dataset_id
        DATASET_ID=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('dataset_id', 'N/A'))" 2>/dev/null)
        echo ""
        echo -e "${GREEN}Dataset ID: $DATASET_ID${NC}"
    else
        echo -e "${RED}❌ Response is not valid JSON${NC}"
        echo "Response:"
        echo "$RESPONSE" | head -20
    fi
else
    echo -e "${RED}❌ Upload failed or timed out (${DURATION}ms)${NC}"
    echo "Response:"
    echo "$RESPONSE" | head -20
fi

# Step 5: Cleanup
echo ""
echo -e "${YELLOW}Step 5: Cleaning up...${NC}"
rm -f "$TEST_FILE"
echo -e "${GREEN}✅ Test file removed${NC}"

echo ""
echo "=========================================="
echo -e "${GREEN}Test complete!${NC}"
echo "=========================================="
