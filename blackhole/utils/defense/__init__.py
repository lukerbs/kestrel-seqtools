"""
Defense modules for screen blanking prevention
"""
from .screen_blanking_defender import (
    apply_driver_block_registry,
    OverlayDefender,
)

__all__ = [
    'apply_driver_block_registry',
    'OverlayDefender',
]

