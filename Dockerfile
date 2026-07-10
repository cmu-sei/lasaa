################################################################################
# TO BUILD:
#   docker build -f Dockerfile -t lasaa . --no-cache
# (You might be able to leave out the "--no-cache")
#
# If you are on a network that requires proxy certificates,
# add them to the `proxy_cert` directory before building.
#
# TO RUN:
#   docker run -it --rm -v ${PWD}:/host [-v addl_mnt] -w /host lasaa bash
#
################################################################################
# <legal>
# LASAA tool
#
# Copyright 2026 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
# INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
# UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS
# TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE
# OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
# MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND
# WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Licensed under a MIT (SEI)-style license, please see License.txt or contact
# permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public
# release and unlimited distribution.  Please see Copyright notice for
# non-US Government use and distribution.
#
# This Software includes and/or makes use of Third-Party Software each subject
# to its own license.
#
# DM26-0426
# </legal>

FROM ubuntu:22.04

# Install packages
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get -y install --no-install-recommends \
         gcc make autoconf zip unzip wget curl gnupg ca-certificates tzdata libstdc++6 \
         pkg-config libfmt-dev libspdlog-dev iputils-ping traceroute libc6-dev \
        && apt-get --purge -y autoremove \
    && apt-get clean

# More packages
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get -y install --no-install-recommends \
         git sqlite3 python3 python3-pip unifdef dos2unix bear less universal-ctags \
         flawfinder gdb bubblewrap ripgrep jq \
    && apt-get --purge -y autoremove \
    && apt-get clean

# Add proxy certificates, if needed.
# (Populate the proxy_cert directory before building the container.)
COPY proxy_cert/ /usr/local/share/ca-certificates/
RUN /usr/sbin/update-ca-certificates
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV AWS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

RUN pip install aiofiles openai pyyaml pandas pyarrow xlrd openpyxl requests

CMD ["/bin/bash"]
