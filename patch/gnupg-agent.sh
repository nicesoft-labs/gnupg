#!/bin/sh

[ -n "${GNUPGHOME-}" ] || GNUPGHOME="$HOME/.gnupg"

if [ -d "$GNUPGHOME" ]; then
	if [ -r "$GNUPGHOME/gpg.conf" ]; then
		CFG="$GNUPGHOME/gpg.conf"
	else
		CFG="$GNUPGHOME/options"
	fi

	if grep -qs '^[[:space:]]*use-agent' "$CFG" &&
	   @LIBEXECDIR@/gnupg/gnupg-agent-wrapper; then
		. "$GNUPGHOME/.gpg-agent-info"
		GPG_TTY="$(tty)"; export GPG_TTY
	fi

	unset CFG
fi
