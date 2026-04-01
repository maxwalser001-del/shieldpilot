#!/bin/bash
cd "/Users/maxwalser/Desktop/Cyber Security Claude"
echo "Starting ShieldPilot server on port 8420..."
python3 -m sentinelai.api.app 2>&1
echo ""
echo "Server exited with code $?. Press Enter to close."
read
