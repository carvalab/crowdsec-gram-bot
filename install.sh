#!/bin/sh
# Install crowdsec-gram-bot on Linux:
#
#   curl -fsSL https://raw.githubusercontent.com/carvalab/crowdsec-gram-bot/main/install.sh | sh
#
# Downloads the latest release for this machine, checks its Ed25519 signature
# and its sha256 checksum, and only then runs `crowdsec-gram-bot install` as
# root. Nothing runs as root before both checks pass.
#
# Without a terminal, `install` reads TELEGRAM_TOKEN and TELEGRAM_ADMIN_ID
# from the environment.
set -eu

main() {
	base=https://github.com/carvalab/crowdsec-gram-bot/releases/latest/download
	pubkey=MCowBQYDK2VwAyEAOCmvuqGInMtB99Rd/1cm261kAtVWFeNaBuafHIIU6Dw=

	[ "$(uname -s)" = Linux ] || die "only Linux is supported"
	case "$(uname -m)" in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) die "unsupported CPU: $(uname -m) (amd64 and arm64 are supported)" ;;
	esac
	for cmd in curl openssl sha256sum; do
		command -v "$cmd" >/dev/null || die "$cmd is required"
	done
	openssl version | grep -q '^OpenSSL [3-9]' || die "OpenSSL 3 or newer is required to check the signature"
	if [ "$(id -u)" -eq 0 ]; then
		sudo=""
	elif command -v sudo >/dev/null; then
		sudo=sudo
	else
		die "run as root, or install sudo"
	fi

	bin=crowdsec-gram-bot_linux_$arch
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	trap 'exit 130' INT TERM
	cd "$tmp"

	say "1/4 downloading $bin"
	curl -fL --connect-timeout 15 --retry 2 --progress-bar -o "$bin" "$base/$bin" || die "download failed"
	curl -fsSL --connect-timeout 15 --retry 2 -o checksums.txt "$base/checksums.txt" || die "download failed"
	curl -fsSL --connect-timeout 15 --retry 2 -o checksums.txt.sig "$base/checksums.txt.sig" || die "download failed"

	say "2/4 checking the signature"
	printf '%s\n' '-----BEGIN PUBLIC KEY-----' "$pubkey" '-----END PUBLIC KEY-----' >release.pub
	openssl pkeyutl -verify -rawin -pubin -inkey release.pub -in checksums.txt -sigfile checksums.txt.sig >/dev/null ||
		die "bad signature on checksums.txt: this release was not signed by the project, do not install it"

	say "3/4 checking the checksum"
	grep " $bin\$" checksums.txt | sha256sum -c - >/dev/null ||
		die "checksum mismatch for $bin: the download is damaged or was changed"
	chmod +x "$bin"

	say "4/4 installing $(./"$bin" version | cut -d' ' -f1)${sudo:+ (sudo may ask for your password)}"
	if (exec </dev/tty) 2>/dev/null; then
		$sudo "./$bin" install </dev/tty
	else
		$sudo "./$bin" install
	fi
}

say() { printf '\033[1m%s\033[0m\n' "$*"; }
die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

main "$@"
