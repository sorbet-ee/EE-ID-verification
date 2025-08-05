#!/bin/bash
#
# Web eID Test Application Launcher
# Starts the Sinatra app via Cloudflare tunnel for HTTPS Web eID testing
#

set -e  # Exit on any error

echo "🌐 Web eID Test Application"
echo "=========================="
echo ""
echo "This will start a local HTTP server and create a secure HTTPS tunnel"
echo "for testing Estonian Web eID authentication with your ID card."
echo ""

# Check if cloudflared is available
if ! command -v cloudflared &> /dev/null; then
    echo "❌ Error: cloudflared is not installed"
    echo ""
    echo "Please install Cloudflare Tunnel:"
    echo "  brew install cloudflared"
    echo "  or download from: https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation/"
    exit 1
fi

# Kill any existing server on port 4567
echo "🧹 Cleaning up any existing server..."
lsof -ti:4567 | xargs kill -9 2>/dev/null || true

# Check if we have the required gems
echo "📦 Checking dependencies..."
if ! bundle check --path=vendor/bundle >/dev/null 2>&1; then
    echo "Installing missing dependencies..."
    bundle install --path=vendor/bundle
fi

# Start the HTTP server in background
echo "🚀 Starting local HTTP server..."
bundle exec ruby run.rb &
SERVER_PID=$!

# Wait for server to start
sleep 3
echo "✅ Server started (PID: $SERVER_PID)"

echo ""
echo "🌐 Creating secure HTTPS tunnel..."
echo "This will give you a public HTTPS URL for Web eID testing"
echo ""

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "🛑 Shutting down..."
    kill $SERVER_PID 2>/dev/null || true
    echo "✅ Server stopped"
    exit 0
}

# Set trap for cleanup
trap cleanup INT TERM

# Start cloudflare tunnel (this blocks until interrupted)
cloudflared tunnel --url http://localhost:4567

# This should not be reached unless cloudflared exits
cleanup