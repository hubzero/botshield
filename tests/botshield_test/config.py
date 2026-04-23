"""Paths and constants the framework needs, all in one place.

Override any of these via env vars before invoking pytest — useful
in CI where paths differ from a dev box, or when running against a
non-default vhost config.
"""

import os

BASE_URL = os.environ.get("BS_BASE", "https://localhost")

# Apache error log that the dev vhost writes its [botshield:*] lines
# to. Every log-assertion fixture slices out of this file.
ERROR_LOG = os.environ.get(
    "BS_ERROR_LOG", "/var/log/apache2/botshield-dev-error.log"
)

# Main Apache error log. A handful of module log lines are emitted
# against the main server_rec (state save from the mod_watchdog
# callback, startup messages) and land here rather than in the
# dev-vhost log. Tests that check for those read this path.
APACHE_ERROR_LOG = os.environ.get(
    "BS_APACHE_ERROR_LOG", "/var/log/apache2/error.log"
)

# Dev vhost config. config_override() edits this file, reloads Apache,
# and reverts on teardown. Never point this at the production vhost.
DEV_VHOST_CONF = os.environ.get(
    "BS_DEV_VHOST_CONF", "/etc/apache2/sites-available/botshield-dev.conf"
)

# Apache service name for systemctl. Some distros call it httpd.
APACHE_SERVICE = os.environ.get("BS_APACHE_SERVICE", "apache2")

# State file on disk — reset fixtures delete this before restarting.
STATE_FILE = os.environ.get("BS_STATE_FILE", "/var/lib/botshield/state.bin")

# Default timeout for a single HTTP call. Tests that intentionally
# exercise slow paths pass their own timeout.
DEFAULT_TIMEOUT = float(os.environ.get("BS_DEFAULT_TIMEOUT", "10"))
