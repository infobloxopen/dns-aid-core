# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""DNS backend implementations: Route53, Infoblox BloxOne, DDNS, Mock."""

from dns_aid.backends.base import DNSBackend
from dns_aid.backends.mock import MockBackend

__all__ = ["DNSBackend", "MockBackend"]

# Route53 is optional - requires boto3
try:
    from dns_aid.backends.route53 import Route53Backend  # noqa: F401

    __all__.append("Route53Backend")
except ImportError:
    pass

# Infoblox BloxOne is optional - uses httpx (already a core dep)
try:
    from dns_aid.backends.infoblox import (  # noqa: F401
        InfobloxBackend,
        InfobloxBloxOneBackend,
    )

    __all__.extend(["InfobloxBackend", "InfobloxBloxOneBackend"])
except ImportError:
    pass

# DDNS backend - uses dnspython (already a core dep)
try:
    from dns_aid.backends.ddns import DDNSBackend  # noqa: F401

    __all__.append("DDNSBackend")
except ImportError:
    pass

# Cloudflare backend - uses httpx (already a core dep)
try:
    from dns_aid.backends.cloudflare import CloudflareBackend  # noqa: F401

    __all__.append("CloudflareBackend")
except ImportError:
    pass
