#!/bin/bash
# Copy of https://web.archive.org/web/20250801123903/https://www.synacktiv.com/en/publications/2025-summer-challenge-ocinception#-the-ultimate-test-script
set -e

# Check args
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <nickname> <loop_count>"
    echo "Give the nickname matching your archive name, and the number of test iterations."
    exit 1
fi

# Check if nickname is not an empty string
if [ -z "$1" ]; then
    echo "Error: nickname arg must not be an empty string."
    exit 1
fi

# Check if loop_count is > 0
if [ "$2" -le 0 ]; then
    echo "Error: loop_count arg must be greater than 0."
    exit 1
fi

INPUT_ARCHIVE_NAME="ocinception_$1.tar"
IMAGE_NAME=ocinception_$1
FINAL_ARCHIVE_NAME="final_${INPUT_ARCHIVE_NAME}"
LOOP_COUNT=$2
MAX_RUN_TIME=8
PODMAN_RUN_OPTIONS=(--network=none --rm --rmi)

#### This command will be run before each test,
#### but it is commented to prevent you from accidentally resetting your entire Podman system
# podman system reset --force

# Load and tag initial podman image
podman load --quiet --input "$INPUT_ARCHIVE_NAME"
current_random_tag=$(head -c 32 /dev/urandom | sha256sum | awk '{print $1}')
podman tag "$IMAGE_NAME:latest" "$IMAGE_NAME:$current_random_tag"

# Podmanception loop
for ((i = 0; i < LOOP_COUNT; i++)); do
    previous_random_tag=$current_random_tag
    current_random_tag=$(head -c 32 /dev/urandom | sha256sum | awk '{print $1}')

    timeout "$MAX_RUN_TIME" podman run "${PODMAN_RUN_OPTIONS[@]}" "$IMAGE_NAME:$previous_random_tag" "$current_random_tag" > "$FINAL_ARCHIVE_NAME"
    podman load --quiet --input "$FINAL_ARCHIVE_NAME" | grep --color "$current_random_tag"
done
podman rmi "$IMAGE_NAME:$current_random_tag" > /dev/null

# Print your score
stat --printf="🦭 Well done little seal! Your score: %s 🦭\n" "$FINAL_ARCHIVE_NAME"
