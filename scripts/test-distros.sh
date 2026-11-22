#!/bin/sh
# Run fixture tests plus actual platform discovery/checks in cached distro images.
# No pulls, host privileges, network, or writable host bind mounts are used.
set -eu
cd "$(dirname "$0")/.."
docker_arch=$(docker info --format '{{.Architecture}}')
case "$docker_arch" in
    x86_64|amd64) target_arch=amd64 ;;
    aarch64|arm64) target_arch=arm64 ;;
    *) echo 'Unsupported Docker architecture' >&2; exit 2 ;;
esac
smoke_dir=$(mktemp -d)
trap 'rm -rf "$smoke_dir"' EXIT HUP INT TERM
CGO_ENABLED=0 GOOS=linux GOARCH="$target_arch" go test -c -o "$smoke_dir/modules.test" ./internal/modules
if [ "$#" -eq 0 ]; then set -- debian ubuntu redhat rocky alpine arch; fi
for profile in "$@"; do
    case "$profile" in
        debian) image=debian:bookworm ;;
        ubuntu) image=ubuntu:24.04 ;;
        redhat) image=registry.access.redhat.com/ubi9/ubi:latest ;;
        rocky) image=rockylinux/rockylinux:9 ;;
        alpine) image=alpine:3.20 ;;
        arch) image=archlinux:latest ;;
        *) echo "Unknown profile: $profile" >&2; exit 2 ;;
    esac
    echo "Testing $profile ($image)"
    docker run --rm --pull=never --network=none --read-only \
        --tmpfs /tmp:rw,nosuid,nodev \
        --mount "type=bind,src=$smoke_dir/modules.test,dst=/secsvc-modules.test,readonly" \
        -e "SECSVC_SMOKE_PROFILE=$profile" \
        --entrypoint /secsvc-modules.test "$image" -test.v
 done
