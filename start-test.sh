#!/bin/bash
#
# Starts the server and three clients (Alice, Bob, Charlie) in separate terminals.
# Supports gnome-terminal, xterm, tmux or screen.
#
# Usage: ./start-test.sh [--debug]

cd "$(dirname "$0")" || exit 1
ROOT="$(pwd)"
SESSION_PREFIX="e2e-study"

DEBUG_FLAG=""
if [ "$1" = "--debug" ]; then
    DEBUG_FLAG="--debug"
    echo "🔍 DEBUG mode on - detailed cryptography logs"
fi

echo "🔐 E2E Encryption Study - starting server + 3 clients (Alice, Bob, Charlie)"
echo "========================================================================="
echo ""

if [ ! -f "config.env" ]; then
    echo "❌ config.env not found!"
    exit 1
fi

# Load environment variables
set -a
# shellcheck disable=SC1091
source config.env
set +a
PORT="${NODE_PORT:-6666}"

# Install dependencies if needed
if [ ! -d "server/node_modules" ] || [ ! -d "client/node_modules" ]; then
    echo "📦 Installing dependencies..."
    (cd server && npm install > /dev/null 2>&1)
    (cd client && npm install > /dev/null 2>&1)
    echo "✅ Dependencies installed"
    echo ""
fi

# Stop a server that is already running on the port
if lsof -i :"$PORT" > /dev/null 2>&1; then
    echo "⚠️  Something is already listening on port $PORT, stopping the existing server..."
    pkill -f "node.*server/server.js" 2>/dev/null
    sleep 2
fi

cleanup() {
    echo ""
    echo "🛑 Stopping all processes..."
    pkill -f "node.*server/server.js" 2>/dev/null
    pkill -f "node.*client/cli/main.js.*--username" 2>/dev/null
    echo "✅ All processes stopped"
    exit 0
}
trap cleanup SIGINT SIGTERM

# Detect the available terminal
if command -v gnome-terminal > /dev/null 2>&1; then
    TERMINAL_CMD="gnome-terminal"
elif command -v xterm > /dev/null 2>&1; then
    TERMINAL_CMD="xterm"
elif command -v tmux > /dev/null 2>&1; then
    TERMINAL_CMD="tmux"
elif command -v screen > /dev/null 2>&1; then
    TERMINAL_CMD="screen"
else
    echo "❌ No terminal multiplexer/emulator found!"
    echo "💡 Install one of: gnome-terminal, xterm, tmux or screen"
    exit 1
fi

echo "📋 Settings:"
echo "   - Server: ${NODE_URL:-http://localhost:$PORT} (port $PORT)"
echo "   - Terminal: $TERMINAL_CMD"
echo ""

# launch <title> <session-suffix> <command>
launch() {
    local title="$1" name="$SESSION_PREFIX-$2" cmd="cd \"$ROOT\" && $3"
    case "$TERMINAL_CMD" in
        gnome-terminal) gnome-terminal --title="$title" -- bash -c "$cmd; exec bash" 2>/dev/null & ;;
        xterm)          xterm -title "$title" -e bash -c "$cmd" 2>/dev/null & ;;
        tmux)           tmux new-session -d -s "$name" "$cmd"
                        echo "   ℹ️  tmux session: $name (tmux attach -t $name)" ;;
        screen)         screen -dmS "$name" bash -c "$cmd"
                        echo "   ℹ️  screen session: $name (screen -r $name)" ;;
    esac
}

echo "🖥️  Starting server..."
launch "Server - port $PORT" "server" "node server/server.js"

echo "⏳ Waiting for the server..."
sleep 3

if ! lsof -i :"$PORT" > /dev/null 2>&1; then
    echo "❌ Error: the server did not start"
    exit 1
fi
echo "✅ Server started!"
echo ""

for user in Alice Bob Charlie; do
    echo "👤 Starting client $user..."
    launch "$user - client" "$(echo "$user" | tr '[:upper:]' '[:lower:]')" \
        "node client/cli/main.js --username $user $DEBUG_FLAG"
    sleep 1
done

echo ""
echo "✅ Everything started!"
echo ""
echo "🚀 Try:"
echo "   - List users:     /users"
echo "   - Start a chat:   /chat Bob        (in Alice's terminal)"
echo "   - Create a group: /group Team"
echo "   - Leave a group:  /leave           (triggers a group re-key)"
echo "   - Show keys:      /keys            (ECDH, Ed25519, TOFU pins)"
if [ -n "$DEBUG_FLAG" ]; then
    echo ""
    echo "🔍 DEBUG mode shows: Ed25519 signatures, TOFU pinning, ECDH secrets,"
    echo "   HKDF derivation, envelope construction and validation"
else
    echo ""
    echo "💡 For detailed logs: ./start-test.sh --debug"
fi
echo ""
echo "🛑 To stop everything: Ctrl+C or pkill -f 'node.*(server/server|client/cli/main).js'"
echo ""

wait
