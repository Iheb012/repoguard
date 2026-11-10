"""Importing this package registers every check. Add new rule modules here."""
from . import (  # noqa: F401
    b64_eval,
    env_exfil,
    legacy,
    npm_lifecycle,
    shell_pipe_exec,
    unicode_hidden,
    vscode_autorun,
)
