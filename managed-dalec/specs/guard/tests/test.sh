#!/bin/bash

# Copyright The Guard Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

# Post-build verification for the guard container image (managed-dalec).
#
# Pulls the built image and confirms the binary actually starts by executing
# its two read-only commands - `--help` and `version`. Fails if either command
# cannot be executed.

: "${REGISTRY:?Required variable REGISTRY is not set}"
: "${REPO:?Required variable REPO is not set}"
: "${TAG:?Required variable TAG is not set}"

IMAGE="${REGISTRY}/${REPO}/guard:${TAG}"

echo "Testing image: ${IMAGE}"

docker pull "${IMAGE}"

if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
    echo "FAIL: image not found after pull: ${IMAGE}"
    exit 1
fi

echo "=== guard --help ==="
docker run --rm "${IMAGE}" --help || {
    echo "FAIL: 'guard --help' could not be executed in ${IMAGE}"
    exit 1
}

echo "=== guard version ==="
docker run --rm "${IMAGE}" version || {
    echo "FAIL: 'guard version' could not be executed in ${IMAGE}"
    exit 1
}

echo "PASS: image starts; '--help' and 'version' both executed successfully"
