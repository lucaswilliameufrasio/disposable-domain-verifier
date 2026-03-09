#!/bin/bash
set -e

BLOCKLIST_URL="https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf"
ASSETS_PATH="assets/blocklist.txt"
TEMP_FILE="assets/blocklist.tmp"

echo "Downloading latest blocklist..."
curl -sSL "$BLOCKLIST_URL" -o "$TEMP_FILE"

# Sanity Check 1: File size (must be at least 10KB and less than 10MB)
FILE_SIZE=$(wc -c <"$TEMP_FILE")
if [ "$FILE_SIZE" -lt 10000 ]; then
    echo "Error: Downloaded file is too small ($FILE_SIZE bytes)."
    rm "$TEMP_FILE"
    exit 1
fi
if [ "$FILE_SIZE" -gt 10485760 ]; then
    echo "Error: Downloaded file is too large ($FILE_SIZE bytes)."
    rm "$TEMP_FILE"
    exit 1
fi

# Sanity Check 2: Must NOT contain common domains
# We check for gmail.com, outlook.com, hotmail.com, yahoo.com, icloud.com
for domain in "gmail.com" "outlook.com" "hotmail.com" "yahoo.com" "icloud.com"; do
    if grep -qi "^$domain$" "$TEMP_FILE"; then
        echo "Error: Sanity check failed! Common domain '$domain' found in blocklist."
        rm "$TEMP_FILE"
        exit 1
    fi
done

# Sanity Check 3: Must contain at least some known disposable domains to ensure it's the right list
# e.g., mailinator.com or 10minutemail.com
FOUND_KNOWN=0
for domain in "mailinator.com" "10minutemail.com" "guerrillamail.com"; do
    if grep -qi "$domain" "$TEMP_FILE"; then
        FOUND_KNOWN=1
        break
    fi
done

if [ "$FOUND_KNOWN" -eq 0 ]; then
    echo "Error: Sanity check failed! No known disposable domains found in the new list."
    rm "$TEMP_FILE"
    exit 1
fi

echo "Sanity checks passed. Updating $ASSETS_PATH..."
mv "$TEMP_FILE" "$ASSETS_PATH"
echo "Done."
