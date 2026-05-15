#!/bin/sh

# Copyright (c) 2026 BKCS <bkcs@hust.edu.vn>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

# otsa-test-mirror — probe a pkg mirror for DNS, HTTP reachability, and
# repository signature validity. Emits a single JSON object to stdout. Exit
# code is always 0 on a clean probe (parseable JSON), reserved for usage
# errors otherwise.

set -u

usage() {
    echo "usage: otsa-test-mirror <mirror-url> [abi]" >&2
    echo "  mirror-url: e.g. http://192.168.150.49 (root URL, no trailing slash)" >&2
    echo "  abi:        OPNsense ABI, defaults to opnsense-version -x" >&2
    exit 64
}

URL=${1-}
ABI=${2-}

if [ -z "${URL}" ]; then
    usage
fi

case "${URL}" in
    http://*|https://*) ;;
    *) usage ;;
esac

if [ -z "${ABI}" ]; then
    if [ -x /usr/local/sbin/opnsense-version ]; then
        ABI=$(/usr/local/sbin/opnsense-version -x)
    fi
fi

if [ -z "${ABI}" ]; then
    echo '{"status":"failure","step":"abi","message":"unable to determine ABI"}'
    exit 0
fi

PKG_ABI=$(pkg config ABI 2>/dev/null)
if [ -z "${PKG_ABI}" ]; then
    PKG_ABI="FreeBSD:14:amd64"
fi

TMPDIR=$(mktemp -d -t otsa-test-mirror) || {
    echo '{"status":"failure","step":"tmp","message":"mktemp failed"}'
    exit 0
}
trap "rm -rf \"${TMPDIR}\"" EXIT INT TERM

# Normalise URL: callers often paste a full repo path like
# `https://pkg.opnsense.org/FreeBSD:14:amd64/26.1/` (i.e. with ABI + release
# already embedded). Strip trailing slashes, then strip a trailing
# `/<PKG_ABI>/<ABI>` if present, so the rest of the script can append the
# canonical `/${PKG_ABI}/${ABI}/latest/...` suffix without doubling the path.
URL=${URL%/}
case "${URL}" in
    *"/${PKG_ABI}/${ABI}")
        URL=${URL%"/${PKG_ABI}/${ABI}"}
        ;;
esac

# Step 1: DNS resolve
HOST=${URL#*://}
HOST=${HOST%%/*}
HOST=${HOST%%:*}

if ! host -t A "${HOST}" >/dev/null 2>&1 && ! host -t AAAA "${HOST}" >/dev/null 2>&1; then
    printf '{"status":"failure","step":"dns","host":"%s","message":"DNS resolution failed"}\n' "${HOST}"
    exit 0
fi

# Step 2: HTTP probe to repo metadata under <URL>/<PKG_ABI>/<ABI>/latest/.
# pkg metadata filename changed across OPNsense releases:
#   - 25.x and older  -> meta.txz  (legacy compressed tar)
#   - 26.1 and newer  -> meta      (raw, packed differently)
# Probe `meta` first (newer + more likely target for OT appliance), fall back
# to `meta.txz` for backward compatibility.
LATEST_URL="${URL}/${PKG_ABI}/${ABI}/latest"
PROBED=""
for META_NAME in meta meta.txz; do
    CANDIDATE="${LATEST_URL}/${META_NAME}"
    if fetch -T 10 -q --no-redirect -o /dev/null "${CANDIDATE}" 2>/dev/null ||
       fetch -T 10 -q -o /dev/null "${CANDIDATE}" 2>/dev/null; then
        PROBED="${CANDIDATE}"
        break
    fi
done
if [ -z "${PROBED}" ]; then
    printf '{"status":"failure","step":"http","url":"%s","message":"repo metadata (meta, meta.txz) unreachable under latest/"}\n' "${LATEST_URL}"
    exit 0
fi

# Step 3: Fetch metadata + verify signature via pkg using an isolated DB.
# Pattern borrowed from src/opnsense/scripts/firmware/connection.sh — never
# taint the active pkg repository state.
export PKG_DBDIR="${TMPDIR}/db"
mkdir -p "${PKG_DBDIR}" "${TMPDIR}/repos"

cat >"${TMPDIR}/repos/test.conf" <<EOF
OTSA-test: {
    url: "${URL}/\${ABI}/${ABI}/latest",
    mirror_type: "srv",
    signature_type: "fingerprints",
    fingerprints: "/usr/local/etc/pkg/fingerprints/OPNsense",
    enabled: yes
}
EOF

OUT="${TMPDIR}/pkg.out"
if pkg -R "${TMPDIR}/repos" -o REPOS_DIR="${TMPDIR}/repos" -o ABI="${PKG_ABI}" \
        update -f -r OTSA-test >"${OUT}" 2>&1; then
    printf '{"status":"ok","dns":"ok","http":"ok","signature":"ok","abi":"%s"}\n' "${ABI}"
else
    MSG=$(tail -n 1 "${OUT}" 2>/dev/null | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/	/ /g')
    if [ -z "${MSG}" ]; then
        MSG="pkg update failed"
    fi
    printf '{"status":"failure","step":"signature","abi":"%s","message":"%s"}\n' "${ABI}" "${MSG}"
fi
