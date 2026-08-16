"""Dotmac Integrator — the connector control-plane deployment.

Composes `dotmac-integration` (the module that owns every connector decision)
with `dotmac-kernel`, and adds only what a deployment can own: configuration,
health, operational controls, worker startup, held secret material and operator
identity.

See `tests/architecture/test_the_assembly_stays_thin.py` for the boundary, which
is enforced rather than described.

## One composition chore, done here because it must happen first

`dotmac_kernel.db` constructs its engines at MODULE IMPORT from the kernel's own
`DATABASE_URL`, and `dotmac_kernel.platform_auth` — the operator guard's
foundation — imports it. So an unset `DATABASE_URL` turns the first import of
this package into `sqlalchemy.exc.ArgumentError: Could not parse SQLAlchemy URL`,
several frames from anything a reader would connect to configuration.

This assembly never uses those engines: it passes its own `Session` to the
kernel's auth predicate and owns every transaction itself. But the DSN still has
to parse, so the environment is made coherent with this deployment's own
resolved configuration before any kernel module is imported. `setdefault`, so an
operator who set it wins; and the value is exactly what `Settings` resolves,
so the kernel cannot end up pointed somewhere this deployment is not.

It lives in `__init__` rather than in `create_app` because a package's
`__init__` runs before any of its submodules, and `create_app` runs long after
`operator_auth` has already imported the kernel.
"""

from __future__ import annotations

import os

from dotmac_integrator.settings import Settings

__version__ = "0.1.0a0"

if not os.environ.get("DATABASE_URL"):
    os.environ["DATABASE_URL"] = Settings().database_url

__all__ = ["__version__"]
