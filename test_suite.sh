#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' 

echo ""
echo "--------------------------------------------------"
echo "SANDBOX TEST SUITE"
echo "--------------------------------------------------"

run_test() {
    local name=$1
    local cmd=$2
    local expected=$3

    echo -n "Testing $name... "
    output=$(sudo ./hermes ./test_payload $cmd 2>&1)

    # -q for quiet, -i for case-insensitive
    if echo "$output" | grep -qi "$expected"; then
        echo -e "${GREEN}PASS${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        echo "   Expected to contain: $expected"
        echo "   Got: $output"
    fi
}

# Use smaller, robust substrings that ignore exact formatting
run_test "Normal Output" "output" "status: 42"
run_test "Time Limit" "timeout" "Time limit exceeded"
run_test "Memory Limit" "memory" "Malloc failed"
run_test "Seccomp Filter" "syscall" "Security breach"
run_test "Filesystem Jail" "jail" "Jail works"

echo ""
echo "--------------------------------------------------"
echo "Tests Complete"
echo "--------------------------------------------------"
echo ""
