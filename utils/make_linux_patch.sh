#!/usr/bin/env bash

cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P

LINUX_PATH="../linux"
OUT_FILE="../linux.patch"

COMMAND="$1"

if [ -z "$COMMAND" ]; then
    echo "Usage: $0 [--create | --apply]"
    echo "--create: Create a patch file from the Linux source directory"
    echo "--apply: Apply the patch file to the Linux source directory"
    exit 1
fi

case "$COMMAND" in
    --create)
        echo "Creating patch file: $OUT_FILE from $LINUX_PATH"
        if [ ! -d "$LINUX_PATH" ]; then
            echo "Error: Linux source directory not found at $LINUX_PATH"
            exit 1
        fi
        (cd "$LINUX_PATH" && git diff > "$(realpath "$OUT_FILE")")
        echo "Patch created successfully."
        ;;
    --apply)
        echo "Applying patch file: $OUT_FILE to $LINUX_PATH"
        if [ ! -f "$OUT_FILE" ]; then
            echo "Error: Patch file not found at $OUT_FILE"
            exit 1
        fi
        if [ ! -d "$LINUX_PATH" ]; then
            echo "Error: Linux source directory not found at $LINUX_PATH"
            exit 1
        fi
        (cd "$LINUX_PATH" && git apply "$(realpath "$OUT_FILE")")
        echo "Patch applied successfully."
        echo " - Note: You may need to commit the changes in $LINUX_PATH before building the kernel."
        ;;
    *)
        echo "Unknown command: $COMMAND"
        echo "Usage: $0 [--create | --apply]"
        exit 1
        ;;
esac
