#!/bin/bash

# @raycast.schemaVersion 1
# @raycast.title Decrypt Clipboard
# @raycast.packageName vaultx
# @raycast.description Decrypt armored vaultx text from clipboard and replace it with the result
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
printf '%s' "$CONTENT" | vaultx decrypt - -p "$1" --armor > "$TMPOUT" 2>/dev/null
STATUS=$?

if [ $STATUS -ne 0 ]; then
  rm -f "$TMPOUT"
  echo "❌ Wrong password or invalid data"
  exit 0
fi

cat "$TMPOUT" | pbcopy
rm -f "$TMPOUT"
echo "✅ Decrypted text copied to clipboard"
