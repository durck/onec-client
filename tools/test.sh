#!/bin/sh
set -eu
task_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$task_root/go-onec"
go test ./...
go vet ./...
go build -trimpath -buildvcs=false -o bin/onec ./cmd/onec
