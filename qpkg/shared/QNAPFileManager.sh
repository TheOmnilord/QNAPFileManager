#!/bin/sh
# QTS App Center service script for QNAPFileManager.
QPKG_NAME="QNAPFileManager"
CONF="/etc/config/qpkg.conf"
QPKG_ROOT=$(/sbin/getcfg "$QPKG_NAME" Install_Path -f "$CONF")
# An empty Install_Path (corrupt qpkg.conf, App Center race) would otherwise
# send every path below to the QTS ramdisk root — including the log that would
# have explained what happened.
if [ -z "$QPKG_ROOT" ]; then
    echo "$QPKG_NAME: Install_Path missing from $CONF — cannot start." >&2
    exit 1
fi
PIDFILE="$QPKG_ROOT/qnapfilemanager.pid"
LOGFILE="$QPKG_ROOT/logs/qfm.log"
CONFIG="$QPKG_ROOT/config/config.json"

export PATH="$QPKG_ROOT/bin:$PATH"
export HOME="$QPKG_ROOT"

# A pid file survives reboots and crashes, and the number in it may have been
# reused by an unrelated process — so check that the pid really is our daemon
# before believing it, and certainly before signalling it.
is_running() {
    [ -f "$PIDFILE" ] || return 1
    pid=$(cat "$PIDFILE" 2>/dev/null)
    case "$pid" in
        ''|*[!0-9]*) return 1 ;;
    esac
    kill -0 "$pid" 2>/dev/null || return 1
    if [ -r "/proc/$pid/cmdline" ]; then
        tr '\0' ' ' < "/proc/$pid/cmdline" | grep -q "qnapfilemanager" || return 1
    fi
    return 0
}

case "$1" in
start)
    ENABLED=$(/sbin/getcfg "$QPKG_NAME" Enable -u -d FALSE -f "$CONF")
    if [ "$ENABLED" != "TRUE" ]; then
        echo "$QPKG_NAME is disabled."
        exit 1
    fi
    if is_running; then
        echo "$QPKG_NAME is already running."
        exit 0
    fi
    mkdir -p "$QPKG_ROOT/logs" "$QPKG_ROOT/config"
    # App Center may invoke this script from a directory that no longer
    # exists; give the daemon a valid cwd.
    cd "$QPKG_ROOT" || exit 1
    if [ ! -x "$QPKG_ROOT/bin/qnapfilemanager" ]; then
        echo "$QPKG_NAME: $QPKG_ROOT/bin/qnapfilemanager is missing or not executable — the package did not install correctly" >&2
        exit 1
    fi
    # QTS's Apache reverse-proxies QPKG_PROXY_PATH to our loopback port. Read
    # it back from qpkg.conf rather than hard-coding it: App Center owns that
    # value, and it is what the daemon mounts its second mux at. It may or may
    # not be stripped before proxying (to be verified on the NAS), so the
    # daemon serves both shapes and this flag only tells it the prefix.
    PROXY_PATH=$(/sbin/getcfg "$QPKG_NAME" Proxy_Path -f "$CONF" 2>/dev/null)
    if [ -n "$PROXY_PATH" ]; then
        PROXY_ARGS="-proxy-prefix $PROXY_PATH"
    else
        PROXY_ARGS=""
    fi
    # -log rather than a shell redirect: the app rotates that file at 8 MiB and
    # keeps one previous generation, which an append-redirect can never do — so
    # a NAS running for years would otherwise grow one unbounded log.
    #
    # The redirect cannot point at the same file: it holds an fd to the inode,
    # so after a rotation renames it the shell would keep growing the
    # generation the app just retired. It goes to its own boot log instead,
    # truncated at every start, which is where a crash before the logger exists
    # (a bad flag, a missing library, a wrong-arch binary) shows up.
    # shellcheck disable=SC2086
    "$QPKG_ROOT/bin/qnapfilemanager" serve -config "$CONFIG" -log "$LOGFILE" $PROXY_ARGS \
        > "$QPKG_ROOT/logs/startup.log" 2>&1 &
    echo $! > "$PIDFILE"
    # Exiting 0 here regardless is how App Center comes to show an app as
    # running when it is not: a wrong-arch binary, a bad flag or an unparsable
    # config all leave the forked shell dead with the reason only in
    # startup.log, while the pidfile holds a pid that no longer exists. Nothing
    # else notices — qpkg.cfg declares no status hook. So look before answering.
    sleep 2
    if ! is_running; then
        echo "$QPKG_NAME: the daemon exited immediately after starting:" >&2
        tail -n 20 "$QPKG_ROOT/logs/startup.log" >&2 2>/dev/null
        rm -f "$PIDFILE"
        exit 1
    fi
    ;;
stop)
    # QPKG_TIMEOUT is "30,60", so there is room to let the daemon drain its
    # per-user workers and running jobs before it is killed.
    if is_running; then
        kill "$(cat "$PIDFILE")" 2>/dev/null
        i=0
        while is_running && [ "$i" -lt 25 ]; do
            sleep 1
            i=$((i + 1))
        done
        is_running && kill -9 "$(cat "$PIDFILE")" 2>/dev/null
    fi
    rm -f "$PIDFILE"
    ;;
restart)
    "$0" stop
    "$0" start
    ;;
*)
    echo "Usage: $0 {start|stop|restart}"
    exit 1
    ;;
esac
exit 0
