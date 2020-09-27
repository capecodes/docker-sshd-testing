#!/bin/bash

# (C) 2017, Cape Codes, <info@cape.codes>
# Dual licensed with MIT and GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

set -e

IMAGE_VERSION="latest"

docker build -t capecodes/sshd-testing:${IMAGE_VERSION} --file Dockerfile .
docker push capecodes/sshd-testing:${IMAGE_VERSION}
