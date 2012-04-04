#!/bin/sh

ACLOCAL="aclocal $ACLOCAL_FLAGS"
export ACLOCAL

(cd $(dirname $0);
 autoreconf --install --force --symlink --verbose &&
 intltoolize --force &&
 autoreconf --force --verbose)

test -n "$NOCONFIGURE" || "$(dirname $0)/configure" "$@"
