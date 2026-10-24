"""Toolbox: two tools that know about each other.

* Network Tool (`nettool`) measures the network - interfaces, capture, VLANs,
  Wi-Fi, interference, packet analysis.
* Assist (`assist`) works a ticket with a model running on this machine, using
  Network Tool's measurements as evidence. Nothing it is given leaves the
  computer.

This package is only the front door: `toolbox net ...` and `toolbox assist ...`
hand straight over to the two, which also remain usable on their own.
"""

__version__ = "0.1.0"
