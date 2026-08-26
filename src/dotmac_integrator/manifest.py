"""The stateless host manifest for this independently deployed assembly.

The integration module owns connector lifecycle and execution. This host owns
only deployment operations whose existence the module cannot declare: held
secret refresh and enablement evidence carrying the platform operator identity.
Those action codes still need the same runtime declaration gate as module-owned
codes, so the host is represented by a normal stateless ``ModuleManifest`` and
composed with ``dotmac_integration.module`` at application construction.
"""

from __future__ import annotations

from dotmac_kernel.modules import ModuleManifest

from dotmac_integrator import __version__

INTEGRATOR_AUDIT_ACTION_PREFIX = "integrator"
INTEGRATOR_AUDIT_ACTIONS: tuple[str, ...] = (
    "integrator.binding.configured",
    "integrator.binding.enabled",
    "integrator.ingress_endpoint.minted",
    "integrator.installation.configured",
    "integrator.installation.drafted",
    "integrator.installation.enabled",
    "integrator.installation.enable_refused",
    "integrator.secrets.refreshed",
    "integrator.shadow_comparison.observed",
)

module = ModuleManifest(
    code="integrator",
    version=__version__,
    core=True,
    dependencies=("integration",),
    audit_actions=INTEGRATOR_AUDIT_ACTIONS,
)

__all__ = [
    "INTEGRATOR_AUDIT_ACTION_PREFIX",
    "INTEGRATOR_AUDIT_ACTIONS",
    "module",
]
