#!/bin/bash

find . -type f -name "*.a" | while read -r lib; do
    matches=$(strings "$lib" | grep -E "Realtek ASDK-|_ver_" | sort -u)
    if [ -n "$matches" ]; then
        echo "========================================"
        echo "Library: $lib"
        echo "----------------------------------------"
        echo "$matches"
        echo
    fi
done