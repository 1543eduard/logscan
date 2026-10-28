#!/bin/bash
# logscan installation script
# Installs global 'logscan' command

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGSCAN_SCRIPT="$SCRIPT_DIR/logscan"

echo "📦 Installing logscan command..."

# Check if script exists
if [ ! -f "$LOGSCAN_SCRIPT" ]; then
  echo "❌ Error: logscan script not found at $LOGSCAN_SCRIPT"
  exit 1
fi

# Make executable
chmod +x "$LOGSCAN_SCRIPT"

# Install to /usr/local/bin
if sudo -n true 2>/dev/null; then
  echo "📝 Copying to /usr/local/bin/logscan..."
  sudo cp "$LOGSCAN_SCRIPT" /usr/local/bin/logscan
  echo "✅ Done! Now you can run: logscan"
else
  # Fallback: install to ~/.local/bin
  mkdir -p ~/.local/bin
  cp "$LOGSCAN_SCRIPT" ~/.local/bin/logscan
  
  # Add to PATH if not already there
  if ! echo "$PATH" | grep -q "$HOME/.local/bin"; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc 2>/dev/null || true
    echo "⚠️  Added $HOME/.local/bin to PATH. Run: source ~/.bashrc"
  fi
  
  echo "✅ Done! Now you can run: logscan"
fi

echo ""
echo "🎉 Installation complete!"
echo ""
echo "Try it:"
echo "  logscan              # Start on port 8080"
echo "  logscan --port 9000  # Start on port 9000"
echo "  logscan --help       # Show help"
