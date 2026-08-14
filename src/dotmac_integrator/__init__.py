"""Dotmac Integrator — the connector control-plane deployment.

Composes `dotmac-integration` (the module that owns every connector decision)
with `dotmac-kernel`, and adds only what a deployment can own: configuration,
health, operational controls, and worker startup.

See `tests/architecture/test_the_assembly_stays_thin.py` for the boundary, which
is enforced rather than described.
"""

from __future__ import annotations

__version__ = "0.1.0a0"

__all__ = ["__version__"]
