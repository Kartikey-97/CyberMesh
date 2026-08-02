"""
CyberMesh SDK
=============

Drop-in Zero-Trust security for any FastAPI microservice.

Usage::

    from cybermesh_sdk import CyberMeshMiddleware, MeshClient

    # 1. Protect your entire service — one line
    app.add_middleware(CyberMeshMiddleware)

    # 2. Make outbound calls through the mesh
    client = MeshClient("order-service")
    response = await client.get("billing-service", "/invoices")
"""

from .middleware import CyberMeshMiddleware
from .client import MeshClient

__all__ = ["CyberMeshMiddleware", "MeshClient"]
__version__ = "1.0.0"
