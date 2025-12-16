#!/bin/sh

set -e
# This script uses helmfile to template Helm charts and outputs them to the current directory
# Adapted from predbat-saas-infra with workaround for https://github.com/helm/helm/issues/12010

OUTPUT_DIR=$(mktemp -d)
TARGET_DIR=$(pwd)

cp helmfile.yaml "$OUTPUT_DIR/"

cd $OUTPUT_DIR

helmfile template --kube-context none --include-crds --skip-tests --args="--no-hooks" --output-dir . \
--output-dir-template '{{ .OutputDir }}'

# Find all directories in the output directory
# mindepth 3 prevents top level directories from being targeted, i.e. the folder containing the kustomization.yaml
find "$OUTPUT_DIR" -mindepth 3 -type d | \
    # Use sed to replace output_dir with target_dir
    sed "s|^$OUTPUT_DIR|$TARGET_DIR|" | \
    # Sort and remove duplicates
    sort -u | \
    # Use xargs to remove directories and files in the target directory
    xargs -n1 rm -rf

# Find all files in the output directory with depth greater than 1
find "$OUTPUT_DIR" -mindepth 2 -type f | while read -r file; do
    # Replace output_dir with target_dir in the file path
    target_file=$(echo "$file" | sed "s|^$OUTPUT_DIR|$TARGET_DIR|")
    # Create the target directory if it doesn't exist
    target_dir=$(dirname "$target_file")
    mkdir -p "$target_dir"
    # Copy the file to the target directory
    cp "$file" "$target_file"
done

echo "✓ Helmfile templates generated successfully"
echo "✓ Output: $TARGET_DIR"
