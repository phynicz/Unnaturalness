#!/bin/bash

# ----------- CONFIGURATION -----------

# args check for directory with decompiled apks output <batch_name> and class files with crypto use output <cipher_name>
if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <search_term> <batch_name> <cipher_name>"
  echo "Example: $0 Cipher.getInstance batch_1 cipher_1"
  exit 1
fi

# Cipher, Apks Source Code DIR, Crypto class files DIR
SEARCH_TERM="$1"
BATCH_NAME="$2"
CIPHER_NAME="$3"

BASE_DIR="$(pwd)"
APK_SOURCE_DIR="$BASE_DIR/apks"
BATCH_OUTPUT_DIR="$BASE_DIR/$BATCH_NAME"
CIPHER_OUTPUT_DIR="$BASE_DIR/$CIPHER_NAME"

# ----------- SETUP -----------

# Create output directories if they don't exist
mkdir -p "$BATCH_OUTPUT_DIR"
mkdir -p "$CIPHER_OUTPUT_DIR"

# Verify APK files directory exists
if [ ! -d "$APK_SOURCE_DIR" ]; then
  echo "APK source directory not found: $APK_SOURCE_DIR"
  exit 1
fi

# ----------- PROCESSING LOOP -----------

for apk_path in "$APK_SOURCE_DIR"/*.apk; do
  apk_file="$(basename "$apk_path")"
  apk_name="${apk_file%.apk}"

  echo "Processing $apk_name"

  decompiled_dir="$BATCH_OUTPUT_DIR/$apk_name"
  resources_dir="$decompiled_dir/resources"
  cipher_apk_dir="$CIPHER_OUTPUT_DIR/$apk_name"

  # Decompile if not already done
  if [ ! -d "$resources_dir" ]; then
    echo "   🔧 Decompiling..."
    mkdir -p "$decompiled_dir"
    jadx -d "$decompiled_dir" --deobf "$apk_path"
  else
    echo "Already decompiled."
  fi

  # Create cipher output directory
  mkdir -p "$cipher_apk_dir"

  # Search and copy matching files
  echo "Finding all '$SEARCH_TERM'..."
  matches=$(grep -ril "$SEARCH_TERM" "$decompiled_dir")

  if [ -n "$matches" ]; then
    echo "$matches" | while read -r match_file; do
      cp "$match_file" "$cipher_apk_dir/"
    done
    echo "Matched class files copied."
  else
    echo "No matches found."
  fi

  echo "Done with $apk_name"
  echo
done

echo "All APKs processed successfully."
