"""
TELLTALE — a passive zero-click / Pegasus-class implant detector for the wire.

  "The endpoint lies. The wire remembers."

The observation boundary is moved off the compromised endpoint (where the
attacker is root and erases their tracks) and onto the network chokepoint — a
home router, a DNS box, a passive tap — where the implant's unavoidable acts
(beacon, exfil, the post-message novel connection) leave invariants it cannot
fully hide.

The name is a double meaning: a *telltale* is the betraying sign, and Dede Korkut
— the ozan — is the teller of the true tale the silence tried to bury.
"""

__version__ = "1.0.0"
__codename__ = "TELLTALE"
__tagline__ = "The endpoint lies. The wire remembers."
