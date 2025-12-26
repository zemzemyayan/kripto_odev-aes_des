import json
import binascii
from typing import Any, Dict

# pack_message:
# Python dict → JSON string → bytes
# TCP sınır tanımadığı için mesajı netleştirmek için \n eklenir
def pack_message(obj: Dict[str, Any]) -> bytes:
    return (json.dumps(obj) + "\n").encode("utf-8")


# unpack_message:
# TCP'den gelen raw bytes → JSON → Python dict
def unpack_message(raw_bytes: bytes):
    try:
        # bytes → string
        s = raw_bytes.decode("utf-8").strip()

        # JSON string → Python dict
        return json.loads(s)
    except Exception:
        return None


# bytes_to_hex:
# bytes → "3baf6b..." gibi string
def bytes_to_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode("ascii")


# hex_to_bytes:
# "3baf6b..." → gerçek byte dizisi
def hex_to_bytes(h: str) -> bytes:
    return binascii.unhexlify(h)
