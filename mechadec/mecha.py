"""
MechaCon platform knowledge: protocol command names and firmware dispatch
tables.

The SPC970 decoder and lifter know nothing about any of this; everything here
is PlayStation 2 MechaCon specific and is applied only once
:func:`mechadec.loader.is_mechacon` has recognised an image.  The command names
and the table shapes follow DiscoStarslayer's ``ghidra-spc970`` analyzer
(``MechaConCommandNames.java`` / ``MechaConAnalyzer.java``).

Table shapes
------------
    SCMD main       4-byte handler pointers, one per command
    SCMD 03 sub     6 bytes: u32 handler, u8 command, u8 parameter count
    NCMD 0/1        6 bytes: u32 handler, u8 flags, u8 parameter count
    PMAP            6 bytes: u8 command, u8 parameter count, u32 handler
    MagicGate       4-byte handler pointers for SCMD 0x80..0x9F
"""

import struct

from . import isa

# ---------------------------------------------------------------------------
# protocol command names
# ---------------------------------------------------------------------------

SCMD_LOW = (
    "Nop", "GetParam", "GetSubq", "Test", "GetErrorLsn", "TrayControl",
    "ClearDspStickyRegister", "SoftReset", "ReadRtc", "WriteRtc", "ReadNvm",
    "WriteNvm", "SetHdMode", "SleepReq", "ResumeReq", "PowerOff", "ReadRtcEcr",
    "WriteRtcEcr", "ReadIlinkId", "WriteIlinkId", "CdCtrlAudioDigitalOut",
    "ForbidDvdPlayer", "AutoAdjustCtrl", "ReadModelNumber", "WriteModelNumber",
    "ForbidRead", "BootCertify", "CancelPowerOffReady", "BlueLedCtrl",
)

SCMD_CONFIG = ("OpenConfig", "ReadConfig", "WriteConfig", "CloseConfig")

NCMD = (
    "Nop", "Reset", "Standby", "Stop", "Pause", "SeekPause", "Read",
    "ReadCd", "ReadDvd", "ReadToc", "Diagnostic", "Test", "ReadKey",
    "ReadTocQ", "ReadXcd",
)

MAGIC_GATE = (
    "Reset", "SessionInit", "WriteChallenge1", "WriteChallenge2",
    "ReadResponse1", "ReadResponse2", "WriteCardResponse",
    "VerifyCardResponse", "GetStatus", "Reserved89", "Reserved8a",
    "Reserved8b", "SetMode", "SetBlockSize", "ReadDataStream",
    "WriteDataStream", "KelfAuthInit", "KelfWriteHeader", "KelfVerify",
    "KelfReadStatus", "DiscAuthPhase1", "DiscAuthPhase2", "DiscAuthPhase3",
    "DiscAuthPhase4", "DiscAuthFinal", "Unknown99", "Unknown9a",
    "ExternalAuthInit", "ExternalAuthChallenge", "ExternalAuthResponse",
    "ExternalSetSize", "ExternalReadResult",
)

PMAP = {
    0x10: "DiscModeCd8", 0x11: "DiscModeCd12", 0x12: "DiscModeDvdSingle8",
    0x13: "DiscModeDvdDual8", 0x14: "DiscModeDvdSingle12",
    0x15: "DiscModeDvdDual12", 0x16: "DiscDetect",
    0x20: "LaserDiode", 0x22: "FocusUpDown", 0x23: "FocusAutoStart",
    0x24: "FocusAutoStop", 0x25: "FocusSearchCheck",
    0x30: "Tracking",
    0x41: "SledControlMicro", 0x42: "SledControlBiphase",
    0x43: "SledControlPosition", 0x44: "SledPositionHome", 0x45: "SledInSwitch",
    0x50: "SpindleControl", 0x51: "SpindleClvS", 0x52: "SpindleClvA",
    0x60: "Tray", 0x61: "TraySwitch",
    0x8D: "ClearConfiguration", 0x8E: "UploadNew", 0x93: "UploadToRam",
    0x97: "DetectAdjust", 0x99: "WriteChecksum", 0x9A: "ReadChecksum",
    0x9B: "SetupOsd", 0x9E: "SetupSanyo",
    0xA1: "AutoAdjustStage1", 0xA2: "AutoAdjustStage2",
    0xA3: "AutoAdjustStage12", 0xA4: "AutoAdjustStage2Md",
    0xA5: "AutoAdjustFixedGain", 0xA7: "RfDcLevel", 0xA8: "Tpp",
    0xAA: "MirrorCheck", 0xAB: "FocusErrorOffset",
    0xB0: "CdPlay1", 0xB1: "CdPlay2", 0xB2: "CdPlay3", 0xB3: "CdPlay4",
    0xB4: "CdStop", 0xB5: "CdPause", 0xB6: "CdTrackControl",
    0xB8: "CdTrackLongControl", 0xB9: "CdPlay5",
    0xC0: "DvdPlay1", 0xC1: "DvdPlay2", 0xC2: "DvdPlay3", 0xC3: "DvdStop",
    0xC4: "DvdPause", 0xC5: "DvdTrackControl", 0xC7: "DvdTrackLongControl",
    0xC8: "FocusJump", 0xCA: "AdjustAutoTilt", 0xCB: "InitializeAutoTilt",
    0xCD: "MoveAutoTilt",
    0xD1: "SetDsp", 0xD3: "Gain", 0xDE: "DspErrorRateControl",
    0xDF: "DspErrorRate",
    0xE0: "EepromWrite", 0xE1: "EepromRead", 0xE4: "RtcRead", 0xE5: "RtcWrite",
    0xE6: "EcrRead", 0xE7: "EcrWrite", 0xE8: "CdError", 0xE9: "Jitter",
    0xF2: "FocusJumpNew", 0xFC: "ReadModel2", 0xFD: "ReadModel",
    0xFE: "EepromErase",
}


def scmd_name(command):
    if command < len(SCMD_LOW):
        return SCMD_LOW[command]
    if 0x40 <= command < 0x40 + len(SCMD_CONFIG):
        return SCMD_CONFIG[command - 0x40]
    if 0x80 <= command < 0x80 + len(MAGIC_GATE):
        return "MagicGate" + MAGIC_GATE[command - 0x80]
    return None


# ---------------------------------------------------------------------------
# byte-signature anchors for known helper routines
# ---------------------------------------------------------------------------

SIGNATURES = {
    "SFR_WriteByte": bytes((
        0xE6, 0x00, 0xF3, 0xDA, 0xF8, 0x04, 0xC8, 0xEF, 0xF3, 0xDD, 0xFD,
        0xA6, 0x08)),
    "SCMD_Command_Dispatcher": bytes((
        0xE6, 0x0C, 0xF3, 0xDA, 0xF8, 0x0C, 0x6B, 0x12, 0x00)),
    "UART_Main_Diagnostic_Loop": bytes((
        0xF3, 0xDA, 0xF8, 0x04, 0xEC, 0xF8, 0x00, 0xFF)),
    "MG_Command_Handler": bytes((
        0xE6, 0x02, 0xF8, 0x0C, 0x6B, 0x00, 0x01, 0xEC)),
    "Compiler_Switch_Dispatch": bytes((
        0xE6, 0x0E, 0xF3, 0xDA, 0xF8, 0x3F, 0x34, 0xC8, 0x10, 0xF2, 0x32,
        0xCC, 0xF3, 0xA4, 0xC8, 0xF3, 0xA4, 0xEF, 0xC0, 0xE2, 0xE8, 0x61,
        0x33, 0x11, 0xC8)),
}

# Offsets of the SFR bit helpers relative to SFR_WriteByte, in the two layouts
# seen across MechaCon revisions.
SFR_HELPER_OFFSETS = (0x00, 0x14, 0x68, 0xB6)
SFR_HELPER_NAMES = ("SFR_WriteByte", "SFR_ReadByte", "SFR_WriteDword",
                    "SFR_ReadDword")
SFR_BIT_LAYOUTS = ((0x16C, 0x1A9, 0x1E6), (0x1A3, 0x1E0, 0x21D))
SFR_BIT_NAMES = ("SFR_SetBit", "SFR_ClearBit", "SFR_TestBit")

MG_SBOX_SIGNATURE = bytes((
    0x0E, 0x00, 0x04, 0x0F, 0x0D, 0x07, 0x01, 0x04, 0x02, 0x0E, 0x0F, 0x02))


# ---------------------------------------------------------------------------
# dispatch-table discovery
# ---------------------------------------------------------------------------


class Tables:
    """Named code entries and data regions recovered from a MechaCon image."""

    def __init__(self):
        self.code_names = {}       # address -> label
        self.data_names = {}       # address -> label
        self.notes = []

    def name_code(self, addr, label):
        if addr not in self.code_names:
            self.code_names[addr] = label

    def name_data(self, addr, label):
        if addr not in self.data_names:
            self.data_names[addr] = label

    @property
    def entries(self):
        return sorted(self.code_names)


def _u8(image, addr, base):
    o = addr - base
    return image[o] if 0 <= o < len(image) else 0


def _u16(image, addr, base):
    o = addr - base
    if o < 0 or o + 2 > len(image):
        return 0
    return struct.unpack_from("<H", image, o)[0]


def _u32(image, addr, base):
    o = addr - base
    if o < 0 or o + 4 > len(image):
        return 0
    return struct.unpack_from("<I", image, o)[0]


def _ptr(image, addr, base, is_code):
    """A stored 32-bit handler, masked to the 24-bit code space."""
    v = _u32(image, addr, base) & isa.ADDR_MASK
    return v if is_code(v) else None


def find(image, needle, start, end, base):
    lo = max(0, start - base)
    hi = min(len(image), end - base)
    idx = bytes(image[lo:hi]).find(needle)
    return base + lo + idx if idx >= 0 else None


def discover(image, base, primary_bank, is_code):
    """Locate the MechaCon dispatch tables and known helpers.

    *is_code* is a predicate telling whether an address lies in an executable
    ROM bank.  Returns a :class:`Tables`."""
    t = Tables()
    bank_end = primary_bank + isa.BANK_SIZE
    rom_end = base + len(image)

    _find_signatures(image, base, primary_bank, bank_end, rom_end, t)
    pmap = _find_pmap(image, base, rom_end, is_code)
    if pmap is not None:
        _mark_pmap(image, base, is_code, pmap, t)
    mg = _find_magic_gate(image, base, primary_bank, is_code)
    if mg is not None:
        _mark_magic_gate(image, base, is_code, mg, t)
    scmd = _find_scmd_sub(image, base, primary_bank, bank_end, is_code)
    if scmd is not None:
        _mark_scmd(image, base, primary_bank, is_code, scmd, t)
    return t


def _find_signatures(image, base, primary_bank, bank_end, rom_end, t):
    sfr = find(image, SIGNATURES["SFR_WriteByte"], primary_bank, bank_end, base)
    if sfr is not None:
        for off, name in zip(SFR_HELPER_OFFSETS, SFR_HELPER_NAMES):
            t.name_code(sfr + off, name)
        for layout in SFR_BIT_LAYOUTS:
            if all(_u8(image, sfr + o, base) == 0xE6 for o in layout):
                for off, name in zip(layout, SFR_BIT_NAMES):
                    t.name_code(sfr + off, name)
                break

    for name in ("SCMD_Command_Dispatcher", "MG_Command_Handler",
                 "Compiler_Switch_Dispatch"):
        hit = find(image, SIGNATURES[name], primary_bank, bank_end, base)
        if hit is not None:
            t.name_code(hit, name)

    uart = find(image, SIGNATURES["UART_Main_Diagnostic_Loop"],
                base + 0x30000, rom_end, base)
    if uart is not None:
        t.name_code(uart, "UART_Main_Diagnostic_Loop")

    sbox = find(image, MG_SBOX_SIGNATURE, primary_bank, primary_bank + 0x8000, base)
    if sbox is not None:
        t.name_data(sbox, "MG_Cipher_SBox_Tables")
        t.notes.append("MagicGate S-box tables at 0x%06X (8 x 64 bytes)" % sbox)


def _count_id_first(image, base, is_code, start, limit, maximum=256):
    """Entries shaped {u8 id, u8 count, u32 handler} with strictly rising ids."""
    count = 0
    previous = -1
    while count < maximum and start + (count + 1) * 6 <= limit:
        entry = start + count * 6
        command = _u8(image, entry, base)
        if _ptr(image, entry + 2, base, is_code) is None or command <= previous:
            break
        previous = command
        count += 1
    return count


def _count_ptr_first(image, base, is_code, start, limit, maximum=128):
    """Entries shaped {u32 handler, u8 id, u8 count}."""
    count = 0
    while count < maximum and start + (count + 1) * 6 <= limit:
        if _ptr(image, start + count * 6, base, is_code) is None:
            break
        count += 1
    return count


def _find_pmap(image, base, rom_end, is_code):
    """The PMAP table is anchored by its run of disc-mode ids 0x14..0x18."""
    start = base + 0x30000
    for addr in range(start, rom_end - 30):
        if (_u8(image, addr, base) == 0x14 and _u8(image, addr + 6, base) == 0x15
                and _u8(image, addr + 12, base) == 0x16
                and _u8(image, addr + 18, base) == 0x17
                and _u8(image, addr + 24, base) == 0x18
                and _ptr(image, addr + 2, base, is_code) is not None
                and _ptr(image, addr + 8, base, is_code) is not None):
            head = addr
            while (head >= start + 6
                   and _ptr(image, head - 4, base, is_code) is not None
                   and _u8(image, head - 6, base) < _u8(image, head, base)):
                head -= 6
            count = _count_id_first(image, base, is_code, head, rom_end)
            if count >= 100:
                return (head, count)
    return None


def _mark_pmap(image, base, is_code, table, t):
    addr, count = table
    t.name_data(addr, "LUT_PMAP_Commands")
    t.notes.append("PMAP command table at 0x%06X, %d entries" % (addr, count))
    for i in range(count):
        entry = addr + i * 6
        command = _u8(image, entry, base)
        handler = _ptr(image, entry + 2, base, is_code)
        if handler is None:
            continue
        name = PMAP.get(command)
        t.name_code(handler, "PMAP_%02X_%s" % (command, name or "Handler"))


def _find_magic_gate(image, base, primary_bank, is_code):
    """A run of 32 in-bank handler pointers in the 0x2000..0x4000 window."""
    lo = primary_bank + 0x2000
    hi = primary_bank + 0x4000 - 128
    for addr in range(lo, hi, 2):
        ok = True
        for i in range(len(MAGIC_GATE)):
            v = _u32(image, addr + i * 4, base) & isa.ADDR_MASK
            if not is_code(v) or not (0x1000 <= (v & 0xFFFF) <= 0x6000):
                ok = False
                break
        if ok:
            return (addr, len(MAGIC_GATE))
    return None


def _mark_magic_gate(image, base, is_code, table, t):
    addr, count = table
    t.name_data(addr, "LUT_SCMD_MagicGate")
    t.notes.append("MagicGate SCMD table at 0x%06X, commands 0x80-0x9F" % addr)
    for i in range(count):
        handler = _ptr(image, addr + i * 4, base, is_code)
        if handler is not None:
            t.name_code(handler, "SCMD_%02X_MG_%s" % (0x80 + i, MAGIC_GATE[i]))
    t.name_data(addr + count * 4, "MG_Cipher_Constants")


def _find_scmd_sub(image, base, primary_bank, bank_end, is_code):
    """SCMD 03 subcommand table, anchored on its 00 01 / 01 01 / 10 / 11 ids."""
    for addr in range(primary_bank, bank_end - 24):
        if (_u8(image, addr + 4, base) == 0x00 and _u8(image, addr + 5, base) == 0x01
                and _u8(image, addr + 10, base) == 0x01
                and _u8(image, addr + 11, base) == 0x01
                and _u8(image, addr + 16, base) == 0x10
                and _u8(image, addr + 22, base) == 0x11
                and _ptr(image, addr, base, is_code) is not None
                and _ptr(image, addr + 6, base, is_code) is not None):
            count = _count_ptr_first(image, base, is_code, addr, bank_end)
            if count >= 40:
                return (addr, count)
    return None


def _mark_scmd(image, base, primary_bank, is_code, table, t):
    addr, count = table
    t.name_data(addr, "LUT_SCMD_03_Subcommands")
    t.notes.append("SCMD 03 subcommand table at 0x%06X, %d entries" % (addr, count))
    for i in range(count):
        entry = addr + i * 6
        handler = _ptr(image, entry, base, is_code)
        if handler is not None:
            t.name_code(handler,
                        "SCMD_03_Subcmd_%02X_Handler" % _u8(image, entry + 4, base))

    main = _find_ptr_table_ending_at(image, base, is_code, addr, 29, 40)
    if main is not None:
        _mark_scmd_main(image, base, is_code, main, t)
        _mark_ncmd(image, base, primary_bank, is_code, main[0], t)

    diag = addr + count * 6
    n = _count_ptr_first(image, base, is_code, diag, primary_bank + isa.BANK_SIZE)
    if n >= 60:
        t.name_data(diag, "LUT_NCMD_0B_Subcommands")
        for i in range(n):
            entry = diag + i * 6
            handler = _ptr(image, entry, base, is_code)
            if handler is not None:
                t.name_code(handler, "NCMD_0B_Subcmd_%02X_Handler"
                            % _u8(image, entry + 4, base))


def _find_ptr_table_ending_at(image, base, is_code, end, minimum, maximum):
    for count in range(maximum, minimum - 1, -1):
        start = end - count * 4
        if all(_ptr(image, start + i * 4, base, is_code) is not None
               for i in range(count)):
            return (start, count)
    return None


def _mark_scmd_main(image, base, is_code, table, t):
    addr, count = table
    t.name_data(addr, "LUT_SCMD_Main_Commands")
    t.notes.append("SCMD main table at 0x%06X, %d commands" % (addr, count))
    for i in range(count):
        handler = _ptr(image, addr + i * 4, base, is_code)
        if handler is None:
            continue
        command = i if i < len(SCMD_LOW) else 0x40 + i - len(SCMD_LOW)
        t.name_code(handler, "SCMD_%02X_%s"
                    % (command, scmd_name(command) or "Handler"))


def _mark_ncmd(image, base, primary_bank, is_code, end, t):
    """Two equal NCMD tables sit immediately below the SCMD main table."""
    start = end
    total = 0
    while (total < 40 and start >= primary_bank + 6
           and _ptr(image, start - 6, base, is_code) is not None):
        start -= 6
        total += 1
    if total < 24 or total % 2:
        return
    count = total // 2
    for index in range(2):
        table_start = start + index * count * 6
        t.name_data(table_start, "LUT_NCMD_Table_%d" % index)
        for i in range(count):
            handler = _ptr(image, table_start + i * 6, base, is_code)
            if handler is None:
                continue
            if index == 1 and i < len(NCMD):
                t.name_code(handler, "NCMD_%02X_%s" % (i, NCMD[i]))
            else:
                t.name_code(handler, "NCMD_Table%d_%02X_Handler" % (index, i))
    t.notes.append("NCMD tables at 0x%06X, %d commands each" % (start, count))
