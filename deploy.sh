#!/usr/bin/env bash

set -Eeuo pipefail

readonly image="disposable-domain-verifier:$(git rev-parse --short=12 HEAD)"
readonly container_prefix="disposable-domain-verifier"

die() {
	printf 'deploy: %s\n' "$1" >&2
	exit 1
}

for command in cargo git ssh tar; do
	command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done

if [[ ! -t 0 || ! -t 1 ]]; then
	die 'run this script in an interactive terminal; no SSH host is configured by default'
fi

read -r -p 'SSH alias from ~/.ssh/config: ' ssh_alias
[[ "$ssh_alias" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$ ]] || die 'enter a valid SSH alias (no default host is configured)'

ssh -o BatchMode=yes -o ConnectTimeout=10 "$ssh_alias" true || die 'SSH connection failed; check the selected alias and key access'
remote_security="$(ssh -o BatchMode=yes "$ssh_alias" docker info --format '{{json .SecurityOptions}}')" || die 'cannot access Docker on the selected host'
[[ "$remote_security" == *'name=rootless'* ]] || die 'remote Docker daemon is not confirmed rootless'

remote_arch="$(ssh -o BatchMode=yes "$ssh_alias" uname -m)" || die 'cannot detect remote CPU architecture'
local_arch="$(uname -m)"
local_os="$(uname -s)"
case "$remote_arch" in
	x86_64|amd64)
		rust_target='x86_64-unknown-linux-gnu'
		remote_arch='x86_64'
		;;
	aarch64|arm64)
		rust_target='aarch64-unknown-linux-gnu'
		remote_arch='aarch64'
		;;
	*) die "unsupported remote CPU architecture: $remote_arch" ;;
esac
case "$local_arch" in
	x86_64|amd64) local_arch='x86_64' ;;
	aarch64|arm64) local_arch='aarch64' ;;
	*) die "unsupported build-machine CPU architecture: $local_arch" ;;
esac

read -r -p 'Host port for the API [9999]: ' host_port
host_port="${host_port:-9999}"
[[ "$host_port" =~ ^[0-9]{1,5}$ ]] && (( host_port > 0 && host_port <= 65535 )) || die 'enter a valid TCP port'

read -r -p 'Remote IPv4 bind address [127.0.0.1]: ' bind_address
bind_address="${bind_address:-127.0.0.1}"
[[ "$bind_address" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die 'enter a valid remote IPv4 address'
IFS=. read -r -a octets <<< "$bind_address"
for octet in "${octets[@]}"; do
	(( 10#$octet <= 255 )) || die 'enter a valid remote IPv4 address'
done

readonly container="${container_prefix}-${host_port}"
existing="$(ssh -o BatchMode=yes "$ssh_alias" docker ps -a --filter "name=^/${container}$" --format '{{.Names}}')" || die 'cannot inspect candidate container on remote host'
replace_existing=0
if [[ -n "$existing" ]]; then
	printf 'Container %s already exists. Replacing it may interrupt its current traffic.\n' "$container"
	read -r -p 'Replace it? [y/N] ' answer
	[[ "$answer" == 'y' || "$answer" == 'Y' ]] || die 'cancelled; existing container was preserved'
	replace_existing=1
fi

printf 'Building %s for the destination architecture (%s)...\n' "$image" "$remote_arch"
temporary_directory="$(mktemp -d)" || die 'cannot create a temporary build directory'
trap 'rm -rf -- "$temporary_directory"' EXIT
context_directory="$temporary_directory/context"
mkdir -m 700 "$context_directory"

if [[ "$local_os" == 'Linux' && "$local_arch" == "$remote_arch" ]]; then
	cargo build --release --locked --bin disposable-domain-verifier || die 'native Rust build failed'
	binary_path='target/release/disposable-domain-verifier'
else
	cargo zigbuild --version >/dev/null 2>&1 || die 'cross-architecture deployment requires cargo-zigbuild and Zig; install them before retrying'
	cargo zigbuild --release --locked --target "$rust_target" --bin disposable-domain-verifier || die 'cargo zigbuild failed'
	binary_path="target/${rust_target}/release/disposable-domain-verifier"
fi

install -m 755 "$binary_path" "$context_directory/disposable-domain-verifier" || die 'cannot stage the compiled Rust binary'
cp -R assets "$context_directory/assets" || die 'cannot stage the runtime assets'
cat >"$context_directory/Dockerfile" <<'DOCKERFILE'
FROM gcr.io/distroless/cc-debian13:nonroot
WORKDIR /app
COPY --chown=nonroot:nonroot disposable-domain-verifier ./disposable-domain-verifier
COPY --chown=nonroot:nonroot assets ./assets
USER nonroot:nonroot
EXPOSE 9999
ENTRYPOINT ["./disposable-domain-verifier"]
DOCKERFILE

printf 'Building the container natively on the destination host (no Buildx/QEMU)...\n'
tar -C "$context_directory" -cf - . |
	ssh -o BatchMode=yes "$ssh_alias" "set -eu; context=\$(mktemp -d); trap 'rm -rf -- \"\$context\"' EXIT; tar -xf - -C \"\$context\"; docker build --tag '$image' \"\$context\""

if (( replace_existing == 1 )); then
	ssh -o BatchMode=yes "$ssh_alias" docker rm -f "$container" || die 'could not remove the confirmed previous container'
fi

ssh -o BatchMode=yes "$ssh_alias" docker run -d \
	--name "$container" \
	--label com.disposable-domain-verifier.managed=true \
	--restart unless-stopped \
	--read-only \
	--tmpfs /tmp:rw,noexec,nosuid,size=16m \
	--cap-drop ALL \
	--security-opt no-new-privileges:true \
	--memory 128m \
	--cpus 0.5 \
	--pids-limit 64 \
	--publish "${bind_address}:${host_port}:9999" \
	--env PORT=9999 \
	"$image"

state="$(ssh -o BatchMode=yes "$ssh_alias" docker inspect --format '{{.State.Status}}' "$container")" || die 'container started but its state could not be inspected'
[[ "$state" == 'running' ]] || die "container is not running (state: $state); inspect its logs on the selected host"

printf '\nContainer %s is running on %s.\n' "$container" "$ssh_alias"
printf 'It listens on %s:%s; configure a reverse proxy to forward to that address and port.\n' "$bind_address" "$host_port"
printf 'Verify the service at /health-check before switching any proxy route. The script does not change DNS or a reverse proxy.\n'
