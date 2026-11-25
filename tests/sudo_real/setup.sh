#!/bin/sh
# Users of the test device. $1: the password of every user; stdin: the public key they accept.
#   pwbash, pwzsh  sudo through the password (the distro's %sudo rule), login shell bash / zsh
#   nopass         a NOPASSWD rule (a key-only device, an old os-teknoir image)
#   shared         password sudo with one sudo login for all the user's processes (timestamp_type=global)
#   nokeep         password sudo that keeps no login between commands (timestamp_timeout=0)
set -eu
password=$1
key=$(cat)
add() {
  useradd -m -s "$2" "$1"
  printf '%s:%s\n' "$1" "$password" | chpasswd
  mkdir -p "/home/$1/.ssh"
  printf '%s\n' "$key" > "/home/$1/.ssh/authorized_keys"
  touch "/home/$1/.zshrc"
  chown -R "$1:" "/home/$1"
  [ "$3" = sudo ] && usermod -aG sudo "$1"
  return 0
}
add pwbash /bin/bash sudo
add pwzsh /bin/zsh sudo
add nopass /bin/bash -
add shared /bin/bash sudo
add nokeep /bin/bash sudo
cat > /etc/sudoers.d/90-test <<'RULES'
Defaults logfile=/var/log/sudo.log
Defaults:shared timestamp_type=global
Defaults:nokeep timestamp_timeout=0
nopass ALL=(ALL:ALL) NOPASSWD: ALL
RULES
chmod 0440 /etc/sudoers.d/90-test
visudo -cq
: > /var/log/sudo.log
exec /usr/sbin/sshd -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o MaxSessions=20
