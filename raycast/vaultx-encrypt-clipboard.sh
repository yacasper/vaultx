#!/bin/bash

# @raycast.schemaVersion 1
# @raycast.title Encrypt Clipboard
# @raycast.packageName vaultx
# @raycast.description Encrypt clipboard text and replace it with the encrypted result
# @raycast.icon 📋
# @raycast.mode compact
# @raycast.argument1 { "type": "password", "placeholder": "Password" }

export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

CONTENT=$(pbpaste)

if [ -z "$CONTENT" ]; then
  echo "❌ Clipboard is empty"
  exit 0
fi

TMPOUT=$(mktemp)
printf '%s' "$CONTENT" | vaultx encrypt - -p "$1" --armor > "$TMPOUT" 2>/dev/null
STATUS=$?

if [ $STATUS -ne 0 ]; then
  rm -f "$TMPOUT"
  echo "❌ Encryption failed"
  exit 0
fi

cat "$TMPOUT" | pbcopy
rm -f "$TMPOUT"
echo "✅ Encrypted text copied to clipboard"
