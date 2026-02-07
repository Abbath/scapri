"""
eCPRI Protocol dissector for Scapy.

Supports eCPRI v1.0/v2.0 header parsing and the following message types:
  0 - IQ Data
  1 - Bit Sequence
  2 - Real-Time Control Data
  3 - Generic Data Transfer
  4 - Remote Memory Access
  5 - One-Way Delay Measurement
  6 - Remote Reset
  7 - Event Indication (with per-element parsing)

Transport bindings: Ethernet (0xAEFE) and UDP (port 6000 default).

Reference: eCPRI Specification V2.0 (2019-05-22)
"""

from scapy.all import (
    Packet,
    BitField,
    BitEnumField,
    ByteEnumField,
    ByteField,
    ShortField,
    IntField,
    LongField,
    XByteField,
    XShortField,
    XIntField,
    StrLenField,
    PacketListField,
    bind_layers,
    Ether,
    UDP,
    Raw,
    rdpcap,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ECPRI_ETHERTYPE = 0xAEFE
ECPRI_UDP_PORT = 6000

ECPRI_MSG_TYPES = {
    0: "IQ Data",
    1: "Bit Sequence",
    2: "Real-Time Control Data",
    3: "Generic Data Transfer",
    4: "Remote Memory Access",
    5: "One-Way Delay Measurement",
    6: "Remote Reset",
    7: "Event Indication",
}

ECPRI_RMA_REQ_RESP = {
    0: "Request",
    1: "Response",
    2: "Failure",
}

ECPRI_RMA_RW = {
    0: "Read",
    1: "Write",
    2: "Read_Write_",
}

ECPRI_RESET_CODE = {
    0x00: "Reserved",
    0x01: "Remote reset request",
    0x02: "Remote reset response",
}

ECPRI_EVENT_TYPE = {
    0x00: "Fault(s) Indication",
    0x01: "Fault(s) Indication Acknowledge",
    0x02: "Notification(s) Indication",
    0x03: "Synchronization Request",
    0x04: "Synchronization Acknowledge",
    0x05: "Synchronization End Indication",
}

ECPRI_RAISE_CEASE = {
    0x0: "Raise a fault",
    0x1: "Cease a fault",
}

# Table 8 from eCPRI spec V2.0 – Fault/Notification numbers
ECPRI_FAULT_NOTIF = {
    0x000: "General Userplane HW Fault",
    0x001: "General Userplane SW Fault",
    0x002: "Unknown",
    0x003: "CPRI Port(s) – Loss of Frame",
    0x004: "CPRI Port(s) – Loss of Sync",
    0x005: "Ethernet Port(s) – Link Down",
    0x006: "Ethernet Port(s) – Frame Loss",
    0x007: "Ethernet Port(s) – Loss of Sync",
    0x008: "Timing – Loss of PTP/SyncE Lock",
    0x009: "Transport – Buffer Overflow",
    0x00A: "Transport – Buffer Underflow",
    # 0x00B – 0x3FF: reserved / vendor-specific
}


# ---------------------------------------------------------------------------
# eCPRI Common Header (4 bytes)
# ---------------------------------------------------------------------------


class eCPRI(Packet):
    """eCPRI common header – present in every eCPRI message."""

    name = "eCPRI"

    fields_desc = [
        BitField("revision", 1, 4),
        BitField("reserved", 0, 3),
        BitField("C", 0, 1),
        ByteEnumField("msg_type", 0, ECPRI_MSG_TYPES),
        ShortField("payload_size", None),
    ]

    def post_build(self, pkt, pay):
        if self.payload_size is None:
            length = len(pay)
            pkt = pkt[:2] + length.to_bytes(2, "big") + pkt[4:]
        return pkt + pay

    def guess_payload_class(self, payload):
        cls_map = {
            0: eCPRI_IQ_Data,
            1: eCPRI_Bit_Sequence,
            2: eCPRI_RT_Control_Data,
            3: eCPRI_Generic_Data_Transfer,
            4: eCPRI_Remote_Memory_Access,
            5: eCPRI_One_Way_Delay,
            6: eCPRI_Remote_Reset,
            7: eCPRI_Event_Indication,
        }
        return cls_map.get(self.msg_type, Raw)


# ---------------------------------------------------------------------------
# Message Type 0 – IQ Data
# ---------------------------------------------------------------------------


class eCPRI_IQ_Data(Packet):
    name = "eCPRI IQ Data"
    fields_desc = [
        XShortField("pc_id", 0),
        ShortField("seq_id", 0),
        StrLenField(
            "iq_data",
            b"",
            length_from=lambda pkt: (
                max(pkt.underlayer.payload_size - 4, 0) if pkt.underlayer else 0
            ),
        ),
    ]

    def extract_padding(self, s):
        return b"", s


# ---------------------------------------------------------------------------
# Message Type 1 – Bit Sequence
# ---------------------------------------------------------------------------


class eCPRI_Bit_Sequence(Packet):
    name = "eCPRI Bit Sequence"
    fields_desc = [
        XShortField("pc_id", 0),
        ShortField("seq_id", 0),
        StrLenField(
            "bit_seq",
            b"",
            length_from=lambda pkt: (
                max(pkt.underlayer.payload_size - 4, 0) if pkt.underlayer else 0
            ),
        ),
    ]

    def extract_padding(self, s):
        return b"", s


# ---------------------------------------------------------------------------
# Message Type 2 – Real-Time Control Data
# ---------------------------------------------------------------------------


class eCPRI_RT_Control_Data(Packet):
    name = "eCPRI RT Control Data"
    fields_desc = [
        XShortField("rtc_id", 0),
        ShortField("seq_id", 0),
        StrLenField(
            "rtc_data",
            b"",
            length_from=lambda pkt: (
                max(pkt.underlayer.payload_size - 4, 0) if pkt.underlayer else 0
            ),
        ),
    ]

    def extract_padding(self, s):
        return b"", s


# ---------------------------------------------------------------------------
# Message Type 3 – Generic Data Transfer
# ---------------------------------------------------------------------------


class eCPRI_Generic_Data_Transfer(Packet):
    name = "eCPRI Generic Data Transfer"
    fields_desc = [
        XIntField("pc_id", 0),
        IntField("seq_id", 0),
        StrLenField(
            "data",
            b"",
            length_from=lambda pkt: (
                max(pkt.underlayer.payload_size - 8, 0) if pkt.underlayer else 0
            ),
        ),
    ]

    def extract_padding(self, s):
        return b"", s


# ---------------------------------------------------------------------------
# Message Type 4 – Remote Memory Access
# ---------------------------------------------------------------------------


class eCPRI_Remote_Memory_Access(Packet):
    name = "eCPRI Remote Memory Access"
    fields_desc = [
        XByteField("rma_id", 0),
        BitEnumField("req_resp", 0, 4, ECPRI_RMA_REQ_RESP),
        BitEnumField("read_write", 0, 4, ECPRI_RMA_RW),
        ShortField("element_id", 0),
        BitField("address", 0, 48),
        ShortField("length", 0),
        StrLenField(
            "data",
            b"",
            length_from=lambda pkt: (
                max(pkt.underlayer.payload_size - 10, 0) if pkt.underlayer else 0
            ),
        ),
    ]

    def extract_padding(self, s):
        return b"", s


# ---------------------------------------------------------------------------
# Message Type 5 – One-Way Delay Measurement
# ---------------------------------------------------------------------------


class eCPRI_One_Way_Delay(Packet):
    name = "eCPRI One-Way Delay Measurement"
    fields_desc = [
        XByteField("measurement_id", 0),
        XByteField("action_type", 0),
        LongField("ts_sec", 0),
        IntField("ts_nsec", 0),
        LongField("compensation_value", 0),
    ]

    def extract_padding(self, s):
        return b"", s


# ---------------------------------------------------------------------------
# Message Type 6 – Remote Reset
# ---------------------------------------------------------------------------


class eCPRI_Remote_Reset(Packet):
    name = "eCPRI Remote Reset"
    fields_desc = [
        XShortField("reset_id", 0),
        ByteEnumField("reset_code", 0, ECPRI_RESET_CODE),
        StrLenField(
            "vendor_specific",
            b"",
            length_from=lambda pkt: (
                max(pkt.underlayer.payload_size - 3, 0) if pkt.underlayer else 0
            ),
        ),
    ]

    def extract_padding(self, s):
        return b"", s


# ---------------------------------------------------------------------------
# Message Type 7 – Event Indication — Element sub-packet
# ---------------------------------------------------------------------------

ECPRI_ELEMENT_SIZE = 8  # bytes per fault/notification element


class eCPRI_Fault_Notification(Packet):
    """
    Single Fault / Notification element inside an Event Indication.

    Layout (8 bytes):
        Element ID          : 2 bytes
        Raise/Cease         : 4 bits
        Fault/Notification  : 12 bits
        Additional Info     : 4 bytes
    """

    name = "eCPRI Fault/Notification Element"

    fields_desc = [
        XShortField("element_id", 0),
        BitEnumField("raise_cease", 0, 4, ECPRI_RAISE_CEASE),
        BitEnumField("fault_notif", 0, 12, ECPRI_FAULT_NOTIF),
        XIntField("additional_info", 0),
    ]

    def extract_padding(self, s):
        """Each element is exactly 8 bytes; remaining bytes are padding."""
        return b"", s


class eCPRI_Event_Indication(Packet):
    """
    Event Indication message (type 7).

    Fixed header (4 bytes) followed by N elements of 8 bytes each,
    where N = number_faults_notif.
    """

    name = "eCPRI Event Indication"

    fields_desc = [
        XByteField("event_id", 0),
        ByteEnumField("event_type", 0, ECPRI_EVENT_TYPE),
        ByteField("sequence_number", 0),
        ByteField("number_faults_notif", 0),
        PacketListField(
            "elements",
            [],
            eCPRI_Fault_Notification,
            count_from=lambda pkt: pkt.number_faults_notif,
            # Each element is exactly 8 bytes
        ),
    ]

    def post_build(self, pkt, pay):
        """Auto-fill number_faults_notif if left at 0 but elements exist."""
        if self.number_faults_notif == 0 and self.elements:
            count = len(self.elements)
            pkt = pkt[:3] + bytes([count]) + pkt[4:]
        return pkt + pay

    def extract_padding(self, s):
        return b"", s


# ---------------------------------------------------------------------------
# Layer bindings
# ---------------------------------------------------------------------------

bind_layers(Ether, eCPRI, type=ECPRI_ETHERTYPE)
bind_layers(UDP, eCPRI, dport=ECPRI_UDP_PORT)
bind_layers(UDP, eCPRI, sport=ECPRI_UDP_PORT)


# ---------------------------------------------------------------------------
# Demo / self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    ps = rdpcap("ecpri.pcap")
    ps.pdfdump("ecpri.pdf")
    for p in ps:
        p.show()
    # # ----- Build an Event Indication with 3 fault elements -----
    # elements = [
    #     eCPRI_Fault_Notification(
    #         element_id=0x0001,
    #         raise_cease=0x0,  # Raise
    #         fault_notif=0x005,  # Ethernet Port(s) – Link Down
    #         additional_info=0xDEADBEEF,
    #     ),
    #     eCPRI_Fault_Notification(
    #         element_id=0x0002,
    #         raise_cease=0x1,  # Cease
    #         fault_notif=0x008,  # Timing – Loss of PTP/SyncE Lock
    #         additional_info=0x00000000,
    #     ),
    #     eCPRI_Fault_Notification(
    #         element_id=0x0003,
    #         raise_cease=0x0,
    #         fault_notif=0x009,  # Transport – Buffer Overflow
    #         additional_info=0xCAFEBABE,
    #     ),
    # ]
    #
    # pkt = (
    #     Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55")
    #     / eCPRI(msg_type=7)
    #     / eCPRI_Event_Indication(
    #         event_id=0x42,
    #         event_type=0x00,  # Fault(s) Indication
    #         sequence_number=1,
    #         number_faults_notif=len(elements),
    #         elements=elements,
    #     )
    # )
    #
    # print("=" * 60)
    # print("  BUILD: Event Indication with 3 fault elements")
    # print("=" * 60)
    # pkt.show2()
    # print()
    #
    # # ----- Round-trip: serialize → parse -----
    # raw_bytes = bytes(pkt)
    # parsed = Ether(raw_bytes)
    #
    # print("=" * 60)
    # print("  PARSED back from raw bytes")
    # print("=" * 60)
    # parsed.show2()
    # print()
    #
    # # ----- Access individual elements programmatically -----
    # evt = parsed[eCPRI_Event_Indication]
    # print(f"Number of elements: {evt.number_faults_notif}")
    # for i, elem in enumerate(evt.elements):
    #     print(
    #         f"  [{i}] element_id=0x{elem.element_id:04X}  "
    #         f"raise_cease={ECPRI_RAISE_CEASE.get(elem.raise_cease)}  "
    #         f"fault={ECPRI_FAULT_NOTIF.get(elem.fault_notif, 'Unknown')}  "
    #         f"info=0x{elem.additional_info:08X}"
    #     )
