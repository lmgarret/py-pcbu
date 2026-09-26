class PCBUError(Exception):
    """Base of the errors raised by py-pcbu."""


class PairingError(PCBUError):
    """The desktop refused the pairing, or closed the connection without answering."""


class UnlockRejectedError(PCBUError, EOFError):
    """The unlock server closed the connection without answering the unlock request:
    the request was rejected (unknown pairing, wrong key or username...) or cancelled."""
