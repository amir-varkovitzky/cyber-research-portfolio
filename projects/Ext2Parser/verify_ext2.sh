#!/bin/bash
set -e

IMAGE="test_fs.img"

# 1. Create a 32MB zeroed file
echo "[*] Creating zeroed image..."
dd if=/dev/zero of=$IMAGE bs=1M count=32 2>/dev/null

# 2. Format as Ext2
echo "[*] Formatting as Ext2..."
mkfs.ext2 -F $IMAGE >/dev/null

# 3. Create dummy files to import
echo "Root File Content" > root_file.txt
echo "Subdir File Content" > sub_file.txt

# 4. Populate using debugfs (no sudo needed)
echo "[*] Populating files via debugfs..."
debugfs -w -R "write root_file.txt /root_file.txt" $IMAGE >/dev/null
debugfs -w -R "mkdir /subdir" $IMAGE >/dev/null
debugfs -w -R "write sub_file.txt /subdir/sub_file.txt" $IMAGE >/dev/null

# 5. Run Ext2Parser against them
echo ""
echo "[*] Testing Root File:"
./ext2_parser $IMAGE /root_file.txt

echo ""
echo "[*] Testing Subdirectory File:"
./ext2_parser $IMAGE /subdir/sub_file.txt

# Cleanup
rm root_file.txt sub_file.txt $IMAGE
