from scapy.all import (
    Packet,
    bind_layers,
    Ether,
    rdpcap,
    Raw,
)
from scapy.fields import (
    BitField,
    ShortField,
    ShortEnumField,
    ByteField,
    IntField,
    Field,
    MACField,
    BitEnumField,
    LongField,
    ByteEnumField,
    PacketListField,
    ConditionalField,
    PacketField,
    MultipleTypeField,
)
from decimal import Decimal, getcontext


class IQData(Packet):
    name = "IQData"
    fields_desc = [ShortField("pc_id", 0), ShortField("seq_id", 0)]


class BitSequence(Packet):
    name = "BitSequence"
    fields_desc = [ShortField("pc_id", 0), ShortField("seq_id", 0)]


class RealTimeControlData(Packet):
    name = "RealTimeControlData"
    fields_desc = [ShortField("rtc_id", 0), ShortField("seq_id", 0)]


class GenericDataTransfer(Packet):
    name = "GenericDataTransfer"
    fields_desc = [IntField("pc_id", 0), IntField("seq_id", 0)]


class RemoteMemoryAccess(Packet):
    name = "RemoteMemoryAccess"
    fields_desc = [
        ByteField("remote_memory_access_id", 0),
        BitEnumField("read_write", 0, 4, {0: "read", 1: "write", 2: "write_no_resp"}),
        BitEnumField("req_resp", 0, 4, {0: "request", 1: "response", 2: "failure"}),
        ShortField("element_id", 0),
        MACField("address", 0),
        ShortField("length", 0),
    ]


class TenField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "10s")

    def i2repr(self, _, x):
        return str(int.from_bytes(x))


class TimeStampField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "10s")

    def i2repr(self, _, x):
        seconds = int.from_bytes(x[0:6])
        nanoseconds = int.from_bytes(x[6:])
        old_prec = getcontext().prec
        getcontext().prec = 19
        res = f"{Decimal(seconds) + Decimal(nanoseconds) * Decimal(1e-9):f}"
        getcontext().prec = old_prec
        return res


class OneWayDelayMeasurement(Packet):
    name = "OneWayDelayMeasurement"
    fields_desc = [
        ByteField("measurement_id", 0),
        ByteEnumField(
            "action_type",
            0,
            {
                0: "request",
                1: "request_with_follow_up",
                2: "response",
                3: "remote_request",
                4: "remote_request_with_follow_up",
                5: "follow_up",
            },
        ),
        TimeStampField("timestamp", 0),
        LongField("compensation_value", 0),
    ]


class RemoteReset(Packet):
    name = "RemoteReset"
    fields_desc = [
        ShortField("reset_id", 0),
        ByteEnumField(
            "reset_code_op", 0, {1: "remote_reset_request", 2: "remote_reset_response"}
        ),
    ]


class Element(Packet):
    name = "Element"
    fields_desc = [
        ShortEnumField("element_id", 0, {0xFFFF: "applicable_for_all_elements"}),
        BitEnumField("raise_cease", 0, 4, {0: "raise_a_fault", 1: "cease_a_fault"}),
        BitEnumField(
            "fault_notif",
            0,
            12,
            {
                0: "general_userplane_hw_fault",
                1: "general_userplane_sw_fault",
                0x400: "unknown_message_type_received",
                0x401: "userplane_data_buffer_underflow",
                0x402: "userplane_data_buffer_overflow",
                0x403: "userplane_data_arrived_too_early",
                0x404: "userplane_data_received_too_late",
            },
        ),
        IntField("additional_information", 0),
    ]


class EventIndication(Packet):
    name = "EventIndication"
    fields_desc = [
        ByteField(
            "event_id",
            0,
        ),
        ByteEnumField(
            "event_type",
            0,
            {
                0: "faults_indication",
                1: "faults_indication_acknowledge",
                2: "notifications_indication",
                3: "synchronization_request",
                4: "synchronization_acknowledge",
                5: "synchronization_end_indication",
            },
        ),
        ByteField("sequence_number", 0),
        ByteField("number_of_faults_notif", 0),  # , fmt="1s", count_of="elements"),
        PacketListField(
            "elements", None, Element, count_from=lambda pkt: pkt.number_of_faults_notif
        ),
    ]


class eCPRI(Packet):
    name = "eCPRI"
    fields_desc = [
        BitField("revision", 2, 4, 1),
        BitField("reserved", 0, 3, 1),
        BitField("C", 0, 1, 1),
        ByteField("message_type", 0),
        ShortField("payload_size", 0),
        MultipleTypeField(
            [
                (
                    PacketField("message", None, IQData),
                    lambda pkt: pkt.message_type == 0,
                ),
                (
                    PacketField("message", None, BitSequence),
                    lambda pkt: pkt.message_type == 1,
                ),
                (
                    PacketField("message", None, RealTimeControlData),
                    lambda pkt: pkt.message_type == 2,
                ),
                (
                    PacketField("message", None, GenericDataTransfer),
                    lambda pkt: pkt.message_type == 3,
                ),
                (
                    PacketField("message", None, RemoteMemoryAccess),
                    lambda pkt: pkt.message_type == 4,
                ),
                (
                    PacketField("message", None, OneWayDelayMeasurement),
                    lambda pkt: pkt.message_type == 5,
                ),
                (
                    PacketField("message", None, RemoteReset),
                    lambda pkt: pkt.message_type == 6,
                ),
                (
                    PacketField("message", None, EventIndication),
                    lambda pkt: pkt.message_type == 7,
                ),
            ],
            PacketField("message", None, Raw),
        ),
    ]


def main():
    bind_layers(Ether, eCPRI, type=0xAEFE)
    ps = rdpcap("ecpri.pcap")
    for p in ps:
        p.show()


if __name__ == "__main__":
    main()
