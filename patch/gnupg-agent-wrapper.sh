#!/bin/sh -efu

[ -n "${GNUPGHOME-}" ] || GNUPGHOME="$HOME/.gnupg"
INFO="$GNUPGHOME/.gpg-agent-info"
>>"$INFO"
enable -f /usr/lib/bash/lockf lockf
builtin lockf "$INFO"

check_agent()
{
	[ -s "$INFO" ] &&
		pid="$(sed -n 's|^GPG_AGENT_INFO=/[^:]\+:\([0-9][0-9]*\):[^:]\+$|\1|p' <"$INFO")" &&
		[ -n "$pid" ] &&
		( [ "$pid" == "0" ] || kill -0 "$pid" 2>/dev/null )
}

check_agent && exit

# Launch seahorse-agent iff
# $DISPLAY is set AND
# (EITHER (pinentry-program is set to seahorse-agent in gpg-agent.conf)
#  OR (no pinentry-program is set in gpg-agent.conf AND seahorse-agent is installed))
# Otherwise launch gpg-agent.

use_seahorse=
if [ -n "${DISPLAY-}" ]; then
	CFG="$GNUPGHOME/gpg-agent.conf"
	if grep -qs '^[[:space:]]*pinentry-program[[:space:]]\+.*seahorse-agent' "$CFG"; then
		use_seahorse=1
	elif ! grep -qs '^[[:space:]]*pinentry-program[[:space:]]' "$CFG" &&
	     type seahorse-agent >/dev/null 2>&1; then
		use_seahorse=1
	fi
fi

if [ -n "$use_seahorse" ]; then
	a=seahorse-agent; $a --variables >"$INFO"
else
    agent_sock=$(gpgconf --list-dirs agent-socket)
cat <<__EOF__ >"$INFO"
GPG_AGENT_INFO=${agent_sock}:0:1; export GPG_AGENT_INFO;
__EOF__
	# no reason to start with new gnupg2 version
	#gpg-agent --daemon
fi

check_agent
