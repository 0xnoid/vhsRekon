#!/bin/bash
run_with_sudo() {
    if [ "$EUID" -ne 0 ]; then
        sudo "$@"
    else
        "$@"
    fi
}

# Detect package manager
if [ -x "$(command -v apt)" ]; then
    LATEST=$(curl -s https://api.github.com/repos/0xnoid/vhsrekon/releases/latest | grep "browser_download_url.*deb" | cut -d '"' -f 4)
    curl -L -o /tmp/vhsrekon.deb "$LATEST"
    run_with_sudo dpkg -i /tmp/vhsrekon.deb
    rm /tmp/vhsrekon.deb
elif [ -x "$(command -v dnf)" ] || [ -x "$(command -v yum)" ]; then
    LATEST=$(curl -s https://api.github.com/repos/0xnoid/vhsrekon/releases/latest | grep "browser_download_url.*rpm" | cut -d '"' -f 4)
    curl -L -o /tmp/vhsrekon.rpm "$LATEST"
    run_with_sudo rpm -i /tmp/vhsrekon.rpm
    rm /tmp/vhsrekon.rpm
elif [ -x "$(command -v pacman)" ]; then
    LATEST=$(curl -s https://api.github.com/repos/0xnoid/vhsrekon/releases/latest | grep "browser_download_url.*pkg.tar.zst" | cut -d '"' -f 4)
    curl -L -o /tmp/vhsrekon.pkg.tar.zst "$LATEST"
    run_with_sudo pacman -U /tmp/vhsrekon.pkg.tar.zst
    rm /tmp/vhsrekon.pkg.tar.zst
else
    echo "Unsupported distribution"
    exit 1
fi

if command -v vhsrekon &> /dev/null; then
    echo "vhsrekon installed successfully! Run 'vhsrekon --help' to get started."
else
    echo "Installation completed but 'vhsrekon' command not found. You may need to restart your terminal."
fi