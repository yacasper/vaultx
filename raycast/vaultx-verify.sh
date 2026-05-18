#!/bin/bash

# @raycast.schemaVersion 1
# @raycast.title Verify File
# @raycast.packageName vaultx
# @raycast.description Verify integrity of a .vx file
# @raycast.icon ✅
# @raycast.mode compact
# @raycast.argument1 { "type": "password", "placeholder": "Password" }

export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"

FILE=$(osascript -e 'POSIX path of (choose file with prompt "Select .vx file to verify:")' 2>/dev/null)

if [ -z "$FILE" ]; then
  echo "Cancelled"
  exit 0
fi

FILE="${FILE%$'\n'}"

if [[ "$FILE" != *.vx ]]; then
  echo "❌ Not a .vx file: $(basename "$FILE")"
  exit 0
fi

OUTPUT=$(vaultx verify "$FILE" -p "$1" 2>&1)

if [ $? -ne 0 ]; then
  if echo "$OUTPUT" | grep -q "wrong password"; then
    echo "❌ Wrong password"
  else
    echo "❌ $(echo "$OUTPUT" | grep '❌' | sed 's/.*❌  //')"
  fi
  exit 0
fi

echo "✅ $(basename "$FILE") is intact"
