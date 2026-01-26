#!/bin/bash

# SIP Management Helper
# Note: Changing SIP status requires booting into Recovery Mode.
# This script helps verify status and provides instructions.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

MODE=$1

check_sip() {
    STATUS=$(csrutil status)
    if [[ "$STATUS" == *"enabled"* ]]; then
        echo "enabled"
    else
        echo "disabled"
    fi
}

current_status=$(check_sip)

echo -e "Current SIP Status: ${YELLOW}$current_status${NC}"

if [ "$MODE" == "disable" ]; then
    if [ "$current_status" == "disabled" ]; then
        echo -e "${GREEN}SIP is already disabled.${NC}"
        exit 0
    fi
    
    echo -e "${RED}Cannot disable SIP from running OS.${NC}"
    echo "You must boot into Recovery Mode to disable SIP."
    echo ""
    echo -e "${YELLOW}Instructions:${NC}"
    echo "1. Restart your Mac."
    echo "2. Hold Command+R (Intel) or Power Button (Apple Silicon) until options appear."
    echo "3. Open Terminal from the Utilities menu."
    echo "4. Run: csrutil disable"
    echo "5. Restart."
    
elif [ "$MODE" == "enable" ]; then
    if [ "$current_status" == "enabled" ]; then
        echo -e "${GREEN}SIP is already enabled.${NC}"
        exit 0
    fi
    
    echo -e "${RED}Cannot enable SIP from running OS.${NC}"
    echo "You must boot into Recovery Mode to enable SIP."
    echo ""
    echo -e "${YELLOW}Instructions:${NC}"
    echo "1. Restart your Mac."
    echo "2. Hold Command+R (Intel) or Power Button (Apple Silicon) until options appear."
    echo "3. Open Terminal from the Utilities menu."
    echo "4. Run: csrutil enable"
    echo "5. Restart."
    
else
    echo "Usage: ./manage_sip.sh [enable|disable]"
fi
