"""BLUETTI Elite 400 device definition."""

from ..base_devices import BaseDeviceV2


class EL400(BaseDeviceV2):
    """Initial EL400 support.

    Keep the first implementation read-only and conservative.  Additional
    registers and controls should be added only after validating them against
    an EL400 raw register dump.
    """
