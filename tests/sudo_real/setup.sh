#!/bin/sh
# Users of the test device. $1: the password of every user; stdin: the public key they accept.
#   pwbash, pwzsh  sudo through the password (the distro's %sudo rule), login shell bash / zsh
#   nopass         a NOPASSWD rule (a key-only device, an old os-teknoir image)
#   k3sonly        password sudo, plus NOPASSWD for k3s alone
#   nokeep         password sudo that keeps no login between commands (timestamp_timeout=0)
#   lock           password sudo; its password is changed by the lockout test
#   shared         password sudo with one sudo login for all the user's processes (timestamp_type=global)
#   loginput       NOPASSWD with sudo input logging (log_input)
#   pwlog          password sudo with sudo input logging
# The last three need sudoers settings sudo-rs does not have. /opt/fake/features lists what this
# device has: its users, `sudo` or `sudo-rs`, and `faillock` (pam_faillock counts failed logins:
# 3 lock the account).
set -eu
password=$1
key=$(cat)
: > /opt/fake/features
add() {
  useradd -m -s "$2" "$1"
  echo "$1" >> /opt/fake/features
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
add k3sonly /bin/bash sudo
add nokeep /bin/bash sudo
add lock /bin/bash sudo
{
  echo 'Defaults:nokeep timestamp_timeout=0'
  echo 'nopass ALL=(ALL:ALL) NOPASSWD: ALL'
  echo 'k3sonly ALL=(ALL:ALL) NOPASSWD: /usr/local/bin/k3s'
} > /etc/sudoers.d/90-test
if sudo --version 2>&1 | grep -qi 'sudo-rs'; then
  echo sudo-rs >> /opt/fake/features
else
  echo sudo >> /opt/fake/features
  add shared /bin/bash sudo
  add loginput /bin/bash -
  add pwlog /bin/bash sudo
  {
    echo 'Defaults logfile=/var/log/sudo.log'
    echo 'Defaults:shared timestamp_type=global'
    echo 'Defaults:loginput,pwlog log_input'
    echo 'loginput ALL=(ALL:ALL) NOPASSWD: ALL'
  } >> /etc/sudoers.d/90-test
fi
chmod 0440 /etc/sudoers /etc/sudoers.d/90-test
visudo -cq
: > /var/log/sudo.log
# pam_faillock the way its manual sets it up, with its defaults spelled out (3 failures in 900 s lock
# the account for 600 s), and deliberately without the `account` line that would clear the count at
# every ssh login: nothing but a sudo login that works resets it here.
if command -v faillock >/dev/null 2>&1 && [ -f /etc/pam.d/common-auth ]; then
  cat > /etc/pam.d/common-auth <<'PAM'
auth    required                        pam_faillock.so preauth silent deny=3 fail_interval=900 unlock_time=600
auth    [success=1 default=ignore]      pam_unix.so nullok
auth    [default=die]                   pam_faillock.so authfail deny=3 fail_interval=900 unlock_time=600
auth    sufficient                      pam_faillock.so authsucc deny=3 fail_interval=900 unlock_time=600
auth    requisite                       pam_deny.so
auth    required                        pam_permit.so
PAM
  echo faillock >> /opt/fake/features
fi
exec /usr/sbin/sshd -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o MaxSessions=20
