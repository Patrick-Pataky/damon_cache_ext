#!/usr/bin/env bash

cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P

LINUX_PATH="../linux"
OUT_FILE="../linux.patch"

COMMAND="$1"

if [ -z "$COMMAND" ]; then
    echo "Usage: $0 [--create | --apply | --reset]"
    echo "--create: Create a patch file from the Linux source directory"
    echo "--apply: Apply the patch file to the Linux source directory"
    echo "--reset: Reset the Linux source directory to the original state"
    exit 1
fi

case "$COMMAND" in
    --create)
        echo "Creating patch file: $OUT_FILE from $LINUX_PATH"
        if [ ! -d "$LINUX_PATH" ]; then
            echo "Error: Linux source directory not found at $LINUX_PATH"
            exit 1
        fi
        (cd "$LINUX_PATH" && git diff 7442a927600ec6ded8ad56a708d293f7cb0d303d > "$(realpath "$OUT_FILE")")
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
    --reset)
        echo "Resetting patch file: $OUT_FILE"
        if [ ! -f "$OUT_FILE" ]; then
            echo "Error: Patch file not found at $OUT_FILE"
            exit 1
        fi
        if [ ! -d "$LINUX_PATH" ]; then
            echo "Error: Linux source directory not found at $LINUX_PATH"
            exit 1
        fi
        (cd "$LINUX_PATH" && git reset --hard 7442a927600ec6ded8ad56a708d293f7cb0d303d)
        echo "Patch reset successfully."
        ;;
    *)
        echo "Unknown command: $COMMAND"
        echo "Usage: $0 [--create | --apply | --reset]"
        exit 1
        ;;
esac
