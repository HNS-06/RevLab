"""
Instruction Representation Module
"""
from dataclasses import dataclass
from typing import Optional

@dataclass
class Instruction:
    address: int
    size: int
    bytes: bytes
    mnemonic: str
    operands: str
    branch_target: Optional[int] = None
    is_call: bool = False
    is_jump: bool = False
    is_ret: bool = False
    is_conditional: bool = False

    @property
    def hex_bytes(self) -> str:
        return self.bytes.hex().upper()

    def __str__(self) -> str:
        return f"0x{self.address:08X}:  {self.hex_bytes:<16} {self.mnemonic:<8} {self.operands}"
