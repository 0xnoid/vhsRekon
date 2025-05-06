#!/usr/bin/env bash
set -e

# sudo?
run_with_sudo() {
    if [ "$EUID" -ne 0 ]; then
        sudo "$@"
    else
        "$@"
    fi
}

# Scope > Local/System
read -rp "Install vhsrekon for current user only? [Y/n]: " choice
    if [[ "$choice" =~ ^[Nn] ]]; then
        INSTALL_SYSTEM=true
    else
        INSTALL_SYSTEM=false
    fi

    # Scope > Determine location
    if $INSTALL_SYSTEM; then
        BIN_DIR="/usr/local/bin"
    else
        BIN_DIR="$HOME/.local/bin"
        mkdir -p "$BIN_DIR"
    fi

# Get version
URL="https://github.com/0xnoid/vhsRekon/releases/download/v0.6.0/vhsrekon"
TMPFILE="$(mktemp)"
    echo "Downloading vhsrekon from $URL…"
    curl -fsSL -o "$TMPFILE" "$URL"

chmod +x "$TMPFILE"
    if $INSTALL_SYSTEM; then
        echo "Installing system-wide to $BIN_DIR…"
        run_with_sudo mv "$TMPFILE" "$BIN_DIR/vhsrekon"
    else
        echo "Installing for current user to $BIN_DIR…"
        mv "$TMPFILE" "$BIN_DIR/vhsrekon"
    fi

echo
echo "✔ vhsrekon installed to $BIN_DIR/vhsrekon"
echo

# Scope > Add to $PATH?
echo "Add $BIN_DIR to your PATH?"
echo "  1) Bash"
echo "  2) Zsh"
echo "  3) Fish"
echo "  S) Skip"
read -rp "Select [1/2/3/S]: " shell_choice

case "$shell_choice" in
    1)
        if $INSTALL_SYSTEM; then
            rc_file="/etc/bash.bashrc"
        else
            rc_file="$HOME/.bashrc"
        fi
        ;;
    2)
        if $INSTALL_SYSTEM; then
            rc_file="/etc/zshrc"
        else
            rc_file="$HOME/.zshrc"
        fi
        ;;
    3)
        if $INSTALL_SYSTEM; then
            rc_file="/etc/fish/config.fish"
        else
            rc_file="$HOME/.config/fish/config.fish"
        fi
        ;;
    [Ss])
        echo "Skipping PATH update."
        exit 0
        ;;
    *)
        echo "Invalid choice; skipping."
        exit 0
        ;;
esac

# Parent $dir
if $INSTALL_SYSTEM; then
    run_with_sudo mkdir -p "$(dirname "$rc_file")"
else
    mkdir -p "$(dirname "$rc_file")"
fi

# Append to .rc and export $PATH
export_line='export PATH="'"$BIN_DIR"':$PATH"'
if $INSTALL_SYSTEM; then
    run_with_sudo bash -c "echo '$export_line' >> '$rc_file'"
else
    echo "$export_line" >> "$rc_file"
fi

echo
echo "✔ Added"
echo "  $export_line"
echo "to $rc_file"
echo
echo "vhsRekon is now ready to use with the command: vhsrekon [OPTION]"
