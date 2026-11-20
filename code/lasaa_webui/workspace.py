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
"""The workspace directory (the --workspace of lasaa_webui_serve.py and
lasaa_webui_import.py) and the paths inside it."""

import os
import re
import secrets
from pathlib import Path

from . import db

class Workspace:
    def __init__(self, root):
        self.root = Path(os.path.expanduser(root)).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.db_path = self.root / "ui.sqlite"
        db.init(self.db_path).close()

    def connect(self):
        return db.connect(self.db_path)

    def path(self, rel):
        """Absolute path of *rel*, a path stored in the database."""
        return self.root / rel

    def rel(self, path):
        return str(Path(path).relative_to(self.root))

    def write_token(self, token):
        """Write the startup token to a mode-0600 file and return its path."""
        path = self.root / "token"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(token + "\n")
        os.chmod(path, 0o600)
        return path


def new_token():
    return secrets.token_urlsafe(32)   # 256 bits


def slugify(name):
    slug = re.sub(r'[^A-Za-z0-9_.-]+', '-', name).strip("-.") or "project"
    return slug[:60]
