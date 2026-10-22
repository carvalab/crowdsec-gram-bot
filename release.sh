#!/bin/sh
# Build, sign and publish a release from this machine:  ./release.sh v1.2.3
#
# The signing key never leaves this machine, so a stolen GitHub token cannot
# publish an update that the servers accept. Servers pick the release up on
# their own within 6 hours.
set -eu
die() { echo "error: $*" >&2; exit 1; }
tag=${1:-}
case "$tag" in v[0-9]*.[0-9]*.[0-9]*) ;; *) die "usage: ./release.sh v1.2.3" ;; esac
key=${RELEASE_SIGNING_KEY_FILE:-$HOME/.config/crowdsec-gram-bot/release-signing-key.pem}
[ -r "$key" ] || die "signing key $key not found"
if ! grep -q 'ENCRYPTED PRIVATE KEY' "$key"; then
  echo "The signing key has no passphrase. Choose one now (keep it in your password manager):"
  if ! (umask 077; openssl pkey -in "$key" -aes256 -out "$key.enc"); then
    rm -f "$key.enc"
    die "could not encrypt the signing key"
  fi
  mv -f "$key.enc" "$key"
fi
grep -q 'ENCRYPTED PRIVATE KEY' "$key" || die "the signing key is still not encrypted"
cd "$(dirname "$0")"
[ "$(git rev-parse --abbrev-ref HEAD)" = main ] || die "release from main"
[ -z "$(git status --porcelain)" ] || die "the working tree is not clean"
git fetch -q origin main
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || die "main is not the same as origin/main"
go test ./...
printf 'Passphrase of the signing key: '
stty -echo
read -r SIGNING_PASSPHRASE
stty echo
echo
pubpem=$(printf '%s' "$SIGNING_PASSPHRASE" | openssl pkey -in "$key" -passin stdin -pubout 2>/dev/null) || die "wrong passphrase"
pub=$(printf '%s\n' "$pubpem" | openssl pkey -pubin -outform DER | tail -c 32 | base64)
grep -q "var PublicKey = \"$pub\"" internal/update/update.go || die "$key does not match PublicKey in internal/update/update.go"
git tag -a "$tag" -m "$tag"
git push origin "$tag"
SIGNING_PASSPHRASE="$SIGNING_PASSPHRASE" SIGNING_KEY_FILE="$key" GITHUB_TOKEN="$(gh auth token)" \
  go run github.com/goreleaser/goreleaser/v2@v2.18.3 release --clean
echo "published $tag; servers install it within 6 hours"
