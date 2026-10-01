RAKWireless/RAK5814-ATECC608A commit 43e45063c08befcaa9ba1000fb9ba4351e051929
https://github.com/RAKWireless/RAK5814-ATECC608A
Modified ECCX08.cpp/.h: removed persistent mutation APIs; added transport opcode allowlist; guarded zero-length memcpy. LGPL license preserved.

v2: receiveResponse uses fixed bounds, exact lengths, initialized storage, CRC, and bounded retry delay; begin checks wake status; bus speed fixed at 100 kHz; unused unsupported APIs removed.
