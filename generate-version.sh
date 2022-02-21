#!/bin/sh

exec 3>&2 2> /dev/null
CWD=$(realpath "$PWD")
TOPLEVEL_WORKING_DIR=$(realpath "$(git rev-parse --show-toplevel)")
exec 2>&3

# If it's not from a git checkout, assume it's from a tarball
if [ "$TOPLEVEL_WORKING_DIR" != "$CWD" ]; then
    VERSION_FROM_DIR_NAME=$(basename "$CWD" | sed -n 's/^accountsservice-\([^-]*\)$/\1/p')

    if [ -n "$VERSION_FROM_DIR_NAME" ]; then
        echo "$VERSION_FROM_DIR_NAME"
        exit 0
    fi

    echo "Source doesn't appear to come from an accountsservice git clone or tarball. Version unknown."
    exit 1
fi

# If it is from a git checkout, derive the version from the date of the last commit, and the number
# of commits since the last release.
COMMITS_SINCE_LAST_RELEASE=$(git rev-list $(git describe --abbrev=0)..HEAD --count)
date +%y.%V.${COMMITS_SINCE_LAST_RELEASE} -d "@$(git log -1 --pretty=format:%ct)"
