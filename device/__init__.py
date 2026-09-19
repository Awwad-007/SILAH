"""SILAH virtual device package."""

from device.tun_tap import IFF_NO_PI, IFF_TAP, TUNSETIFF, TunTapDevice

__all__ = ["TunTapDevice", "TUNSETIFF", "IFF_TAP", "IFF_NO_PI"]
