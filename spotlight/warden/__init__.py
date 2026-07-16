"""Warden — the control plane that stops the swarm from being turned against
the customer.

Public surface:

    WardenService  — main service class (envelope, scans, capabilities, signing)
    Warden         — alias of WardenService for concise call-sites
    InjectionMatch — one prompt-injection hit
    BackdoorMatch  — one backdoor / weakening hit
"""
from .backdoor_check import BackdoorMatch
from .injection_detector import InjectionMatch
from .service import Warden, WardenService

__all__ = [
    "Warden",
    "WardenService",
    "InjectionMatch",
    "BackdoorMatch",
]
