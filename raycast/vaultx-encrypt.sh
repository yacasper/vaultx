#!/bin/bash

# @raycast.schemaVersion 1
# @raycast.title Encrypt File
# @raycast.packageName vaultx
# @raycast.description Encrypt a file or folder with vaultx
# @raycast.icon 🔐
# @raycast.mode compact
# @raycast.argument1 { "type": "password", "placeholder": "Password" }
# @raycast.argument2 { "type": "password", "placeholder": "Confirm password" }

export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"

if [ "$1" != "$2" ]; then
  echo "❌ Passwords do not match"
  exit 0
fi

FILE=$(osascript <<'EOF'
set choice to button returned of (display dialog "What to encrypt?" buttons {"File", "Folder", "Cancel"} default button "File")
if choice is "Cancel" then return ""
if choice is "File" then
  return POSIX path of (choose file with prompt "Select file to encrypt:")
else
  return POSIX path of (choose folder with prompt "Select folder to encrypt:")
end if
EOF
)

if [ -z "$FILE" ]; then
  echo "Cancelled"
  exit 0
fi

FILE="${FILE%$'\n'}"

OUTPUT=$(vaultx encrypt "$FILE" -p "$1" 2>&1)

if [ $? -ne 0 ]; then
  echo "❌ $(echo "$OUTPUT" | grep '❌' | sed 's/.*❌  //')"
  exit 0
fi

echo "✅ Encrypted: $(basename "$FILE")"
