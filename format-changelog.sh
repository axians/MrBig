#!/usr/bin/env bash
set -euo pipefail

DRY_RUN=0
FILE="ChangeLog"

for arg in "$@"; do
    case "$arg" in
        --dry-run)
            DRY_RUN=1
            ;;
        *)
            FILE="$arg"
            ;;
    esac
done

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

last_date=""
prev_blank=1
changed=0
line_no=0

validate_date() {
    if date -d "$1" '+%F' >/dev/null 2>&1; then
        return 0
    elif date -j -f "%Y-%m-%d" "$1" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

while IFS= read -r line || [[ -n "$line" ]]; do
    ((++line_no))

    original="$line"

    # Normalize CRLF
    line="${line%$'\r'}"

    # Replace tabs
    line="${line//$'\t'/        }"

    # Remove trailing whitespace
    line="${line%"${line##*[![:space:]]}"}"

    if [[ -z "$line" ]]; then
        if (( ! prev_blank )); then
            echo >> "$TMP"
        fi
        prev_blank=1
        continue
    fi

    # Header — accept both YYYY-MM-DD and YYMMDD (normalised to YYYY-MM-DD)
    is_header=0
    if [[ "$line" =~ ^[[:space:]]*([0-9]{4}-[0-9]{2}-[0-9]{2})[[:space:]]+(.*)$ ]]; then
        entry_date="${BASH_REMATCH[1]}"
        summary="${BASH_REMATCH[2]}"
        is_header=1
    elif [[ "$line" =~ ^[[:space:]]*([0-9]{2})([0-9]{2})([0-9]{2})[[:space:]]+(.*)$ ]]; then
        entry_date="20${BASH_REMATCH[1]}-${BASH_REMATCH[2]}-${BASH_REMATCH[3]}"
        summary="${BASH_REMATCH[4]}"
        is_header=1
    fi

    if (( is_header )); then

        if ! validate_date "$entry_date"; then
            echo "Error: $FILE:$line_no: invalid date '$entry_date'." >&2
            exit 2
        fi

        if [[ -n "$last_date" && "$entry_date" > "$last_date" ]]; then
            echo "Error: $FILE:$line_no: out-of-order entry. '$entry_date' should appear above '$last_date' because the changelog is ordered newest first." >&2
            exit 2
        fi

        last_date="$entry_date"

        if [[ -s "$TMP" ]] && (( ! prev_blank )); then
            echo >> "$TMP"
        fi

        printf "%s %s\n" "$entry_date" "$summary" >> "$TMP"

        if [[ "$original" != "$entry_date $summary" ]]; then
            changed=1
        fi

        prev_blank=0
        continue
    fi

    # Continuation line
    stripped="${line#"${line%%[![:space:]]*}"}"
    fixed="    $stripped"

    printf "%s\n" "$fixed" >> "$TMP"

    if [[ "$original" != "$fixed" ]]; then
        changed=1
    fi

    prev_blank=0

done < "$FILE"

# Compare whole file to catch blank line changes
if ! cmp -s "$FILE" "$TMP"; then
    changed=1
fi

if (( DRY_RUN )); then
    if (( changed )); then
        echo "Formatting changes required."
        echo "  - Run $0 without --dry-run to apply changes."
        exit 1
    else
        echo "Already formatted."
        exit 0
    fi
fi

if (( changed )); then
    mv "$TMP" "$FILE"
    echo "Formatted $FILE"
else
    echo "$FILE already formatted."
fi
