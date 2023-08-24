import logging
import time
from enum import IntEnum
from random import randint
from typing import Optional, Callable, Sequence, Dict, Tuple

from uhid import UHIDDevice, _ReportType, AsyncioBlockingUHID, Bus
from fido2.pcsc import CtapDevice, CTAPHID, CtapError, CtapPcscDevice

SECONDS_TO_WAIT_FOR_AUTHENTICATOR = 10
"""How long, in seconds, to poll for a USB authenticator before giving up."""
VID = 0x9999
"""USB vendor ID."""
PID = 0x9999
"""USB product ID."""

BROADCAST_CHANNEL = bytes([0xFF, 0xFF, 0xFF, 0xFF])
"""Standard CTAP-HID broadcast channel."""


class CommandType(IntEnum):
    """Catalog of CTAP-HID command type bytes."""
    PING = 0x01
    MSG = 0x03
    INIT = 0x06
    WINK = 0x08
    CBOR = 0x10
    CANCEL = 0x11
    KEEPALIVE = 0x3B
    ERROR = 0x3F


def _wrap_call_with_device_obj(device: UHIDDevice,
                               call: Callable[[UHIDDevice, Sequence[int], _ReportType], None]) -> Callable:
    """Pass a UHIDDevice to a given callback."""
    return lambda x, y: call(device, x, y)


class CTAPHIDDevice:
    device: UHIDDevice
    """Underlying UHID device."""
    channels_to_devices: Dict[str, CtapDevice] = {}
    """Mapping from channel strings to CTAP devices."""
    channels_to_state: Dict[str, Tuple[CommandType, int, int, bytes]] = {}
    """
    Mapping from channel strings to receive buffer state.

    Each value consists of:
    1. The command type in use on the channel
    2. The total length of the incoming request
    3. The sequence number of the most recently received packet (-1 for initial)
    4. The accumulated data received on the channel
    """
    reference_count = 0
    """Number of open handles to the device: clear state when it hits zero."""
    fixed_device: Optional[CtapDevice] = None
    """Optional CtapDevice to which to proxy, instead of discovering one over PC/SC"""

    def __init__(self, fixed_device: Optional[CtapDevice] = None):
        self.fixed_device = fixed_device
        self.device = UHIDDevice(
            vid=VID, pid=PID, name='FIDO2 Virtual USB Device', report_descriptor=[
                0x06, 0xD0, 0xF1,  # Usage Page (FIDO)
                0x09, 0x01,  # Usage (CTAPHID)
                0xa1, 0x01,  # Collection (Application)
                0x09, 0x20,  # Usage (Data In)
                0x15, 0x00,  # Logical min (0)
                0x26, 0xFF, 0x00,  # Logical max (255)
                0x75, 0x08,  # Report Size (8)
                0x95, 0x40,  # Report count (64 bytes per packet)
                0x81, 0x02,  # Input(HID_Data | HID_Absolute | HID_Variable)
                0x09, 0x21,  # Usage (Data Out)
                0x15, 0x00,  # Logical min (0)
                0x26, 0xFF, 0x00,  # Logical max (255)
                0x75, 0x08,  # Report Size (8)
                0x95, 0x40,  # Report count (64 bytes per packet)
                0x91, 0x02,  # Output(HID_Data | HID_Absolute | HID_Variable)
                0xc0,        # End Collection
            ],
            backend=AsyncioBlockingUHID,
            version=0,
            bus=Bus.USB
        )

        self.device.receive_output = self.process_hid_message
        self.device.receive_close = self.process_close
        self.device.receive_open = self.process_open

    def process_open(self):
        self.reference_count += 1

    def process_close(self):
        self.reference_count -= 1
        if self.reference_count == 0:
            # Clear all state
            self.channels_to_devices = {}
            self.channels_to_state = {}

    def process_hid_message(self, buffer: Sequence[int], report_type: _ReportType) -> None:
        """Core method: handle incoming HID messages."""
        recvd_bytes = bytes(buffer)
        logging.debug(f"GOT MESSAGE (type {report_type}): {recvd_bytes.hex()}")

        if self.is_initial_packet(recvd_bytes):
            channel, lc, cmd, data = self.parse_initial_packet(recvd_bytes)
            channel_key = self.get_channel_key(channel)
            logging.debug(f"CMD {cmd.name} CHANNEL {channel_key} len {lc} (recvd {len(data)}) data {data.hex()}")
            self.channels_to_state[channel_key] = cmd, lc, -1, data
            if lc == len(data):
                # Complete receive
                self.finish_receiving(channel)
        else:
            channel, seq, new_data = self.parse_subsequent_packet(recvd_bytes)
            channel_key = self.get_channel_key(channel)
            if channel_key not in self.channels_to_state:
                self.send_error(channel, 0x0B)
                return
            cmd, lc, prev_seq, existing_data = self.channels_to_state[channel_key]
            if seq != prev_seq + 1:
                self.handle_cancel(channel, b"")
                self.send_error(channel, 0x04)
                return
            remaining = lc - len(existing_data)
            data = bytes([x for x in existing_data] + [x for x in new_data[:remaining]])
            self.channels_to_state[channel_key] = cmd, lc, seq, data
            logging.debug(f"After receive, we have {len(data)} bytes out of {lc}")
            if lc == len(data):
                self.finish_receiving(channel)

    async def start(self):
        await self.device.wait_for_start_asyncio()

    def parse_initial_packet(self, buffer: bytes) -> Tuple[bytes, int, CommandType, bytes]:
        """Parse an incoming initial packet."""
        logging.debug(f"Initial packet {buffer.hex()}")
        channel = buffer[1:5]
        cmd_byte = buffer[5] & 0x7F
        lc = (int(buffer[6]) << 8) + buffer[7]
        data = buffer[8:8+lc]
        cmd = CommandType(cmd_byte)
        return channel, lc, cmd, data

    def is_initial_packet(self, buffer: bytes) -> bool:
        """Return true if packet is the start of a new sequence."""
        if buffer[5] & 0x80 == 0:
            return False
        return True

    def assign_channel_id(self) -> Sequence[int]:
        """Create a new, random, channel ID."""
        return [randint(0, 255), randint(0, 255),
                randint(0, 255), randint(0, 255)]

    def handle_init(self, channel: bytes, buffer: bytes) -> Optional[Sequence[int]]:
        """Initialize or re-initialize a channel."""
        logging.debug(f"INIT on channel {channel}")

        new_channel = self.assign_channel_id()

        ctap = self.get_pcsc_device(new_channel)
        if ctap is None:
            return None

        if channel == BROADCAST_CHANNEL:
            assert len(buffer) == 8
            return ([x for x in buffer] +
                    new_channel +
                    [
                        0x02,  # protocol version
                        0x01,  # device version major
                        0x00,  # device version minor
                        0x00,  # device version build/point
                        ctap.capabilities,  # capabilities, from the underlying device
                    ])
        else:
            self.handle_cancel(channel, b"")

    def get_pcsc_device(self, channel_id: Sequence[int]) -> Optional[CtapDevice]:
        """Grab a PC/SC device from python-fido2, or use a fixed one if present."""
        channel_key = self.get_channel_key(channel_id)

        if channel_key not in self.channels_to_devices:
            if self.fixed_device is not None:
                self.channels_to_devices[channel_key] = self.fixed_device
            else:
                start_time = time.time()
                while time.time() < start_time + SECONDS_TO_WAIT_FOR_AUTHENTICATOR:
                    devices = list(CtapPcscDevice.list_devices())
                    if len(devices) == 0:
                        time.sleep(0.1)
                        continue
                    device = devices[0]
                    self.channels_to_devices[channel_key] = device
                    return device
                # TODO: send timeout error properly
                raise ValueError("Could not connect to a PC/SC device in time!")
                # self.send_error(channel_id, 0x05)
                # return None

        return self.channels_to_devices[channel_key]

    def handle_cbor(self, channel: Sequence[int], buffer: bytes) -> Optional[Sequence[int]]:
        """Handling an incoming CBOR command."""
        ctap = self.get_pcsc_device(channel)
        if ctap is None:
            return None
        logging.debug(f"Sending CBOR to device {ctap}: {buffer}")
        try:
            res = ctap.call(cmd=CommandType.CBOR, data=buffer)
            return [x for x in res]
        except CtapError as e:
            logging.info(f"Got CTAP error response from device: {e}")
            return [e.code]

    def handle_cancel(self, channel: Sequence[int], buffer: bytes) -> Optional[Sequence[int]]:
        channel_key = self.get_channel_key(channel)
        if channel_key in self.channels_to_state:
            del self.channels_to_state[channel_key]
        if channel_key in self.channels_to_devices:
            del self.channels_to_devices[channel_key]
        return []

    def handle_wink(channel: Sequence[int], buffer: bytes) -> Optional[Sequence[int]]:
        """Do nothing; this can't be done over PC/SC."""
        return []

    def handle_msg(self, channel: Sequence[int], buffer: bytes) -> Optional[Sequence[int]]:
        """Process a U2F/CTAP1 message."""
        device = self.get_pcsc_device(channel)
        if device is None:
            return None
        res = device.call(CTAPHID.MSG, buffer)
        return [x for x in res]

    def handle_ping(self, channel: Sequence[int], buffer: bytes) -> Optional[Sequence[int]]:
        """Handle an echo request."""
        return [x for x in buffer]

    def handle_keepalive(self, channel: Sequence[int], buffer: bytes) -> Optional[Sequence[int]]:
        """Placeholder: always returns that the device is processing."""
        return [1]

    def encode_response_packets(self, channel: Sequence[int], cmd: CommandType, data: Sequence[int]) -> Sequence[bytes]:
        """Chunk response data to be delivered over USB."""
        offset_start = 0
        seq = 0
        responses = []
        while offset_start < len(data):
            if seq == 0:
                capacity = 64 - 7
                chunk = data[offset_start:offset_start + capacity]
                data_len_upper = len(data) >> 8
                data_len_lower = len(data) % 256
                response = [x for x in channel] + [cmd | 0x80, data_len_upper, data_len_lower] + chunk
            else:
                capacity = 64 - 5
                chunk = data[offset_start:offset_start + capacity]
                response = [x for x in channel] + [seq - 1] + chunk

            while len(response) < 64:
                response.append(0x00)

            responses.append(bytes(response))
            offset_start += capacity
            seq += 1

        return responses

    def get_channel_key(self, channel: Sequence[int]) -> str:
        return bytes(channel).hex()

    def send_error(self, channel: Sequence[int], error_type: int) -> None:
        responses = self.encode_response_packets(channel, CommandType.ERROR, [error_type])
        for response in responses:
            self.device.send_input(response)

    def finish_receiving(self, channel: Sequence[int]) -> None:
        """When finished receiving packets, act on them."""
        channel_key = self.get_channel_key(channel)
        cmd, _, _, data = self.channels_to_state[channel_key]
        self.handle_cancel(channel, b"")

        try:
            handler = getattr(self, f"handle_{cmd.name.lower()}", None)
            if handler is not None:
                response_body = handler(channel, data)
                if response_body is None:
                    # Already dealt with
                    return
                responses = self.encode_response_packets(channel, cmd, response_body)
            else:
                self.send_error(channel, 0x01)
                return
        except Exception as e:
            logging.warning(f"Error: {e}")
            self.send_error(channel, 0x7F)
            return

        for response in responses:
            self.device.send_input(response)

    def parse_subsequent_packet(self, data: bytes) -> Tuple[Sequence[int], int, bytes]:
        """Parse a non-initial packet."""
        return data[1:5], data[5], bytes(data[6:])
