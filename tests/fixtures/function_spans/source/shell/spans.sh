#!/usr/bin/env bash
LIMIT=4 # ANCHOR:none

load_items() { # BEGIN:load_items
    local dir="$1" # ANCHOR:load_items
    echo "${#dir} }" # ANCHOR:load_items
} # END:load_items

function render { # BEGIN:render
    for item in "$@"; do
        printf '%s\n' "$item" # ANCHOR:render
    done
} # END:render

load_items "$HOME"
