#!/bin/bash
# build.sh - Compile and link sysmon.asm
# Requires: nasm, ld (binutils)

set -e

echo "[*] Checking for NASM..."
if ! command -v nasm &>/dev/null; then
    echo "[!] NASM not found. Install with:"
    echo "    sudo apt install nasm         # Debian/Ubuntu"
    echo "    sudo dnf install nasm         # Fedora/RHEL"
    echo "    sudo pacman -S nasm           # Arch"
    exit 1
fi

echo "[*] Assembling sysmon.asm → sysmon.o ..."
nasm -f elf64 sysmon.asm -o sysmon.o

echo "[*] Linking sysmon.o → sysmon ..."
ld -o sysmon sysmon.o

rm -f sysmon.o

echo "[+] Build successful!"
echo ""
echo "Run with:  ./sysmon"
echo "Exit with: Ctrl+C"
