"""Import this deployment before any kernel module, in every test session.

`dotmac_kernel.db` constructs its engines at MODULE IMPORT from the kernel's own
`DATABASE_URL`, and `dotmac_kernel.platform_auth` imports it. So a test module
whose first kernel import happens before `dotmac_integrator` has been imported
gets `sqlalchemy.exc.ArgumentError: Could not parse SQLAlchemy URL` during
COLLECTION — before a single assertion runs, and several frames from anything a
reader would connect to configuration.

`dotmac_integrator.__init__` makes the environment coherent with this
deployment's own resolved settings (see its docstring). pytest loads conftest
before any test module, so importing it here guarantees the ordering that
`uvicorn --factory dotmac_integrator.assembly:create_app` gets for free.

Import order inside a test module is decided by the formatter, not by the
author, which is exactly why this cannot be left to one.
"""

from __future__ import annotations

import dotmac_integrator  # noqa: F401  — imported for its import-time effect
