"""Port of LibSnaffle/ActiveDirectory/Sysvol/GpoFiles/PolGpoFile.cs

Represents a .pol file found within a GPO directory.

PORT NOTE: the C# walks the file with a `BinaryReader` constructed over
`Encoding.Unicode`, so every `ReadChar()` consumes **two** bytes and `ReadString`
(the private one below, not BinaryReader's) accumulates UTF-16LE code units until
a NUL. `ReadUInt32` reads four raw little-endian bytes regardless of the
encoding. The byte walk here is a literal transcription of that, including the
unchecked enum cast, the `\\0` -> space scrub for string types, and the fact that
a truncated record raises rather than being tolerated.
"""

import struct

from ..settings import RegHive, RegistrySetting, RegistryValue, RegKeyValType
from .dotnet_compat import enum_cast
from .gpo_file import GpoFile

SIGNATURE = 0x67655250

# PORT NOTE: REG_BINARY (and other non-string registry types) must never be
# decoded as UTF-16 for display. Random cert/key blobs (e.g. EFSBlob) decode
# into CJK mojibake. value_bytes always keeps the raw bytes for analysis;
# value_string carries the full hex so the report has the complete blob.
def _format_binary_display(raw: bytes) -> str:
    if not raw:
        return "<binary, 0 bytes>"
    return f"<binary, {len(raw)} bytes> {raw.hex()}"


class _Reader:
    """The bits of System.IO.BinaryReader(stream, Encoding.Unicode) that are used."""

    def __init__(self, data: bytes):
        self.data = data
        self.position = 0

    @property
    def length(self) -> int:
        return len(self.data)

    def _take(self, count: int) -> bytes:
        if self.position + count > len(self.data):
            # EndOfStreamException equivalent.
            raise EOFError
        chunk = self.data[self.position : self.position + count]
        self.position += count
        return chunk

    def read_uint32(self) -> int:
        return struct.unpack("<I", self._take(4))[0]

    def read_char(self) -> str:
        return self._take(2).decode("utf-16-le", errors="replace")

    def read_bytes(self, count: int) -> bytes:
        # BinaryReader.ReadBytes returns fewer bytes at end of stream rather than
        # throwing, so this is a clamped read.
        chunk = self.data[self.position : self.position + count]
        self.position += len(chunk)
        return chunk


class PolGpoFile(GpoFile):
    """Port of LibSnaffle.ActiveDirectory.PolGpoFile."""

    def __init__(self, filepath: str, fs, logger=None):
        super().__init__(filepath, fs, logger)
        self.signature = 0
        self.version = 0

    def parse(self) -> None:
        self.get_settings()

    def get_settings(self) -> None:
        reader = _Reader(self.fs.read_file(self.file_path))

        self.signature = reader.read_uint32()
        if self.signature != SIGNATURE:
            # NotSupportedException equivalent.
            raise ValueError("File format is not supported")
        self.version = reader.read_uint32()

        length = reader.length
        while reader.position < length:
            setting = RegistrySetting(source=self.file_path)
            reader.read_char()
            key_path = self.read_string(reader)
            split_key_path = key_path.split("\\")
            #  these don't say a hive, the hive is determined by whether it's user policy or machine policy, so it's always either hkcu or hklm.
            # PORT NOTE: the original compares against "\machine\" and "\user\"
            # because it only ever sees Windows paths. An offline SYSVOL copy on
            # Linux yields "/Machine/Registry.pol", which would match neither and
            # throw away the whole file, so the path is normalised to backslashes
            # first and the original's comparisons are then kept verbatim.
            lowered_file_path = self.file_path.lower().replace("/", "\\")
            if "\\machine\\" in lowered_file_path:
                setting.hive = RegHive.HKEY_LOCAL_MACHINE
            elif "\\user\\" in lowered_file_path:
                setting.hive = RegHive.HKEY_CURRENT_USER
            else:
                raise NotImplementedError(
                    "Something went wrong trying to figure out the hive associated with this registry.pol file:"
                    + self.file_path
                )
            setting.key = "\\".join(split_key_path[1:])
            reader.read_char()
            reg_val = RegistryValue(value_name=self.read_string(reader))
            reader.read_char()
            reg_val.reg_key_val_type = enum_cast(RegKeyValType, reader.read_uint32())
            reader.read_char()
            setting_size = reader.read_uint32()
            reader.read_char()
            reg_val.value_bytes = reader.read_bytes(setting_size)
            vtype = reg_val.reg_key_val_type
            if vtype == RegKeyValType.REG_DWORD and len(reg_val.value_bytes) >= 4:
                key_int = struct.unpack_from("<i", reg_val.value_bytes, 0)[0]
                reg_val.value_string = str(key_int)
            elif vtype == RegKeyValType.REG_DWORD_BIG_ENDIAN and len(reg_val.value_bytes) >= 4:
                key_int = struct.unpack_from(">i", reg_val.value_bytes, 0)[0]
                reg_val.value_string = str(key_int)
            elif vtype == RegKeyValType.REG_QWORD and len(reg_val.value_bytes) >= 8:
                key_int = struct.unpack_from("<q", reg_val.value_bytes, 0)[0]
                reg_val.value_string = str(key_int)
            elif vtype in (
                RegKeyValType.REG_SZ,
                RegKeyValType.REG_EXPAND_SZ,
                RegKeyValType.REG_MULTI_SZ,
                RegKeyValType.REG_LINK,
            ):
                dirtystring = reg_val.value_bytes.decode("utf-16-le", errors="replace")
                reg_val.value_string = dirtystring.replace("\0", " ")
            else:
                reg_val.value_string = _format_binary_display(reg_val.value_bytes)
            reader.read_char()
            setting.values.append(reg_val)
            self.settings.append(setting)

    @staticmethod
    def read_string(reader: _Reader) -> str:
        """Port of PolGpoFile.ReadString."""
        temp = ""
        while True:
            current = reader.read_char()
            if current == "\0":
                break
            temp += current

        return temp
