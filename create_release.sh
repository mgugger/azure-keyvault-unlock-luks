#!/bin/bash

FILE_TO_ZIP="target/x86_64-unknown-linux-gnu/release/luks_unlocker"
OUTPUT_ZIP="azure-keyvault-unlock-luks_x86_64.zip"

zip -j "$OUTPUT_ZIP" "$FILE_TO_ZIP"

if [ $? -ne 0 ]; then
    echo "Error: Failed to create zip file."
    exit 1
fi

SHA256SUM_FILE="${OUTPUT_ZIP}.sha256"

sha256sum "$OUTPUT_ZIP" > "$SHA256SUM_FILE"

if [ $? -ne 0 ]; then
    echo "Error: Failed to create SHA256 checksum."
    exit 1
fi

echo "Created zip file: $OUTPUT_ZIP"
echo "Created SHA256 checksum file: $SHA256SUM_FILE"