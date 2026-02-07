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
  7 - Event Indication

Transport bindings: Ethernet (0xAEFE) and UDP (port 6000 default).

Reference: eCPRI Specification V2.0 (2019-05-22)
"""

from scapy.all import (
    Packet,
    BitField,
    BitEnumField,
    ByteEnumField,
    ShortField,
    IntField,
    LongField,
    XByteField,
    XShortField,
    XIntField,
    StrLenField,
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
ECPRI_UDP_PORT = 6000  # common default; not strictly standardized

ECPRI_MSG_TYPES = {
    0: "IQ Data",
    1: "Bit Sequence",
    2: "Real-Time Control Data",
    3: "Generic Data Transfer",
    4: "Remote Memory Access",
    5: "One-Way Delay Measurement",
    6: "Remote Reset",
    7: "Event Indication",
    # 8-63 reserved, 64-255 vendor specific
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


# ---------------------------------------------------------------------------
# eCPRI Common Header (4 bytes)
# ---------------------------------------------------------------------------


class eCPRI(Packet):
    """eCPRI common header – present in every eCPRI message."""

    name = "eCPRI"

    fields_desc = [
        BitField("revision", 1, 4),
        BitField("reserved", 0, 3),
        BitField("C", 0, 1),  # concatenation indicator
        ByteEnumField("msg_type", 0, ECPRI_MSG_TYPES),
        ShortField("payload_size", None),
    ]

    def post_build(self, pkt, pay):
        """Auto-compute payload_size if not set."""
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
        XShortField("pc_id", 0),  # eAxC identifier
        ShortField("seq_id", 0),  # sequence ID
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
        # 6-byte (48-bit) address stored in an 8-byte field (top 2 bytes 0)
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
        # Timestamps are 10 bytes each: 6B seconds + 4B nanoseconds
        # We store them as raw bytes for fidelity.
        LongField("ts_sec", 0),  # truncated: see note
        IntField("ts_nsec", 0),
        LongField("compensation_value", 0),  # 8 bytes
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
# Message Type 7 – Event Indication
# ---------------------------------------------------------------------------


class eCPRI_Event_Indication(Packet):
    name = "eCPRI Event Indication"
    fields_desc = [
        XByteField("event_id", 0),
        ByteEnumField("event_type", 0, ECPRI_EVENT_TYPE),
        XByteField("sequence_number", 0),
        XByteField("number_faults_notif", 0),
        StrLenField(
            "element_data",
            b"",
            length_from=lambda pkt: (
                max(pkt.underlayer.payload_size - 4, 0) if pkt.underlayer else 0
            ),
        ),
    ]

    def extract_padding(self, s):
        return b"", s


# ---------------------------------------------------------------------------
# Layer bindings
# ---------------------------------------------------------------------------

# Ethernet transport
bind_layers(Ether, eCPRI, type=ECPRI_ETHERTYPE)

# UDP transport (common default port)
bind_layers(UDP, eCPRI, dport=ECPRI_UDP_PORT)
bind_layers(UDP, eCPRI, sport=ECPRI_UDP_PORT)


# ---------------------------------------------------------------------------
# Quick demo / self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    ps = rdpcap("ecpri.pcap")
    ps.pdfdump("ecpri.pdf")
    for p in ps:
        p.show()
    # # --- Build an IQ Data message over Ethernet ---
    # pkt_eth = (
    #     Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55")
    #     / eCPRI(msg_type=0)
    #     / eCPRI_IQ_Data(pc_id=0x1234, seq_id=1, iq_data=b"\xab\xcd" * 8)
    # )
    # print("=== eCPRI IQ Data over Ethernet ===")
    # pkt_eth.show2()
    # print()
    #
    # # Round-trip: rebuild from bytes
    # raw_bytes = bytes(pkt_eth)
    # parsed = Ether(raw_bytes)
    # print("=== Parsed back from bytes ===")
    # parsed.show2()
    # print()
    #
    # # --- Build a One-Way Delay message over UDP ---
    # from scapy.all import IP
    #
    # pkt_udp = (
    #     IP(dst="10.0.0.1")
    #     / UDP(dport=ECPRI_UDP_PORT)
    #     / eCPRI(msg_type=5)
    #     / eCPRI_One_Way_Delay(
    #         measurement_id=0x01,
    #         action_type=0x00,
    #         ts_sec=1000,
    #         ts_nsec=500000,
    #         compensation_value=0,
    #     )
    # )
    # print("=== eCPRI One-Way Delay over UDP ===")
    # pkt_udp.show2()
    # print()
    #
    # # --- Build a Remote Reset message ---
    # pkt_reset = (
    #     Ether(dst="ff:ff:ff:ff:ff:ff")
    #     / eCPRI(msg_type=6)
    #     / eCPRI_Remote_Reset(
    #         reset_id=0x0001,
    #         reset_code=0x01,
    #         vendor_specific=b"\xde\xad",
    #     )
    # )
    # print("=== eCPRI Remote Reset ===")
    # pkt_reset.show2()
