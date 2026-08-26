#!/bin/bash
# DataGuard Agent — Start Script
# Usage:
#   ./start.sh          → local only (http://localhost:3000)
#   ./start.sh --tunnel → local + public internet URL via Cloudflare

echo ""
echo "🛡  DataGuard Agent"
echo "═══════════════════════════════════"

if [[ "$1" == "--tunnel" ]]; then
  echo "🌐 Mode: Public (Cloudflare Tunnel)"
  echo "   A public URL will appear below in ~10 seconds"
  echo ""
  node server.js --tunnel
else
  echo "💻 Mode: Local only"
  echo "   Open: http://localhost:3000"
  echo ""
  echo "   Tip: Run './start.sh --tunnel' to get a public URL"
  echo ""
  node server.js
fi
