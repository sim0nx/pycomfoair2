#
# Copyright (c) 2020 Andreas Oberritter
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

import logging
import re
from struct import pack

from comfoair.model import DataType, IntType, StrType, TempType

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class CAReponse:
  def __init__(self, cmd: int, offset: int, size: int, data_type: type[DataType], label: str | None = None) -> None:
    if label is None:
      self.label = 'unknown response'
    else:
      self.label = label

    self.cmd = cmd
    self.offset = offset
    self.size = size
    self.data_type = data_type

  def __eq__(self, other: object) -> bool:
    if not isinstance(other, CAReponse):
      return False

    return self.cmd == other.cmd and self.offset == other.offset and self.size == other.size and self.data_type == other.data_type

  def __hash__(self) -> int:
    concat = f'{self.label}|{self.cmd:#x}|{self.offset}|{self.size}|{self.data_type}'
    return hash(concat)

  def __str__(self) -> str:
    return f'command: {self.label} {self.cmd:#04x} offset: {self.offset} size: {self.size} type: {self.data_type}'


RESPONSES = {
  0x68: [
    CAReponse(0x68, 0, 3, IntType, label='BOOTLOADER_VERSION'),
    CAReponse(0x68, 3, 10, StrType, label='BOOTLOADER_NAME'),
  ],
  0x6A: [
    CAReponse(0x6A, 0, 3, IntType, label='FIRMWARE_VERSION'),
    CAReponse(0x6A, 3, 10, StrType, label='FIRMWARE_NAME'),
  ],
  0xA2: [
    CAReponse(0xA2, 0, 2, IntType, label='CONNECTOR_BOARD_VERSION'),
    CAReponse(0xA2, 2, 10, StrType, label='CONNECTOR_BOARD_NAME'),
    CAReponse(0xA2, 12, 1, IntType, label='CC_EASE_VERSION'),
    CAReponse(0xA2, 13, 1, IntType, label='CC_LUXE_VERSION'),
  ],
  0x0C: [
    CAReponse(0x0C, 0, 1, IntType, label='VENT_SUPPLY_PERC'),
    CAReponse(0x0C, 1, 1, IntType, label='VENT_RETURN_PERC'),
    CAReponse(0x0C, 2, 2, IntType, label='VENT_SUPPLY_RPM'),
    CAReponse(0x0C, 4, 2, IntType, label='VENT_RETURN_RPM'),
  ],
  0x0E: [
    CAReponse(0x0E, 0, 1, IntType, label='BYPASS_STATUS'),
  ],
  0x10: [
    CAReponse(0x10, 0, 1, TempType, label='TEMP_STATUS_OUTSIDE'),
    CAReponse(0x10, 1, 1, TempType, label='TEMP_STATUS_SUPPLY'),
    CAReponse(0x10, 2, 1, TempType, label='TEMP_STATUS_RETURN'),
    CAReponse(0x10, 3, 1, TempType, label='TEMP_STATUS_EXHAUST'),
  ],
  0xCE: [
    CAReponse(0xCE, 0, 1, IntType, label='VENT_SET_EXHAUST_0'),
    CAReponse(0xCE, 1, 1, IntType, label='VENT_SET_EXHAUST_1'),
    CAReponse(0xCE, 2, 1, IntType, label='VENT_SET_EXHAUST_2'),
    CAReponse(0xCE, 3, 1, IntType, label='VENT_SET_SUPPLY_0'),
    CAReponse(0xCE, 4, 1, IntType, label='VENT_SET_SUPPLY_1'),
    CAReponse(0xCE, 5, 1, IntType, label='VENT_SET_SUPPLY_2'),
    CAReponse(0xCE, 6, 1, IntType, label='AIRFLOW_EXHAUST'),
    CAReponse(0xCE, 7, 1, IntType, label='AIRFLOW_SUPPLY'),
    CAReponse(0xCE, 8, 1, IntType, label='FAN_SPEED_MODE'),
    CAReponse(0xCE, 9, 1, IntType, label='FAN_MODE_SUPPLY'),
    CAReponse(0xCE, 10, 1, IntType, label='VENT_SET_EXHAUST_3'),
    CAReponse(0xCE, 11, 1, IntType, label='VENT_SET_SUPPLY_3'),
  ],
  0xD2: [
    CAReponse(0xD2, 0, 1, TempType, label='TEMP_COMFORT'),
    CAReponse(0xD2, 1, 1, TempType, label='TEMP_OUTSIDE'),
    CAReponse(0xD2, 2, 1, TempType, label='TEMP_SUPPLY'),
    CAReponse(0xD2, 3, 1, TempType, label='TEMP_RETURN'),
    CAReponse(0xD2, 4, 1, TempType, label='TEMP_EXHAUST'),
  ],
  0xDA: [
    CAReponse(0xDA, 8, 1, IntType, label='ERRORS_FILTER'),
  ],
  0xDE: [
    CAReponse(0xDE, 15, 2, IntType, label='RUNNING_HOURS_FILTER'),
  ],
}

BOOTLOADER_VERSION = CAReponse(0x68, 0, 3, IntType)
BOOTLOADER_NAME = CAReponse(0x68, 3, 10, StrType)

FIRMWARE_VERSION = CAReponse(0x6A, 0, 3, IntType)
FIRMWARE_NAME = CAReponse(0x6A, 3, 10, StrType)

CONNECTOR_BOARD_VERSION = CAReponse(0xA2, 0, 2, IntType)
CONNECTOR_BOARD_NAME = CAReponse(0xA2, 2, 10, StrType)
CC_EASE_VERSION = CAReponse(0xA2, 12, 1, IntType)
CC_LUXE_VERSION = CAReponse(0xA2, 13, 1, IntType)

VENT_SUPPLY_PERC = CAReponse(0x0C, 0, 1, IntType)
VENT_RETURN_PERC = CAReponse(0x0C, 1, 1, IntType)
VENT_SUPPLY_RPM = CAReponse(0x0C, 2, 2, IntType)
VENT_RETURN_RPM = CAReponse(0x0C, 4, 2, IntType)

BYPASS_STATUS = CAReponse(0x0E, 0, 1, IntType)

TEMP_STATUS_OUTSIDE = CAReponse(0x10, 0, 1, TempType)
TEMP_STATUS_SUPPLY = CAReponse(0x10, 1, 1, TempType)
TEMP_STATUS_RETURN = CAReponse(0x10, 2, 1, TempType)
TEMP_STATUS_EXHAUST = CAReponse(0x10, 3, 1, TempType)

VENT_SET_EXHAUST_0 = CAReponse(0xCE, 0, 1, IntType)
VENT_SET_EXHAUST_1 = CAReponse(0xCE, 1, 1, IntType)
VENT_SET_EXHAUST_2 = CAReponse(0xCE, 2, 1, IntType)
VENT_SET_SUPPLY_0 = CAReponse(0xCE, 3, 1, IntType)
VENT_SET_SUPPLY_1 = CAReponse(0xCE, 4, 1, IntType)
VENT_SET_SUPPLY_2 = CAReponse(0xCE, 5, 1, IntType)
AIRFLOW_EXHAUST = CAReponse(0xCE, 6, 1, IntType)
AIRFLOW_SUPPLY = CAReponse(0xCE, 7, 1, IntType)
FAN_SPEED_MODE = CAReponse(0xCE, 8, 1, IntType)
FAN_MODE_SUPPLY = CAReponse(0xCE, 9, 1, IntType)
VENT_SET_EXHAUST_3 = CAReponse(0xCE, 10, 1, IntType)
VENT_SET_SUPPLY_3 = CAReponse(0xCE, 11, 1, IntType)

TEMP_COMFORT = CAReponse(0xD2, 0, 1, TempType)
TEMP_OUTSIDE = CAReponse(0xD2, 1, 1, TempType)
TEMP_SUPPLY = CAReponse(0xD2, 2, 1, TempType)
TEMP_RETURN = CAReponse(0xD2, 3, 1, TempType)
TEMP_EXHAUST = CAReponse(0xD2, 4, 1, TempType)

ERRORS_FILTER = CAReponse(0xDA, 8, 1, IntType)

RUNNING_HOURS_FILTER = CAReponse(0xDE, 15, 2, IntType)


class ComfoAirBase:
  _BAUD_RATE = 9600

  __MSG_ESC = b'\x07'
  __MSG_START = __MSG_ESC + b'\xf0'
  __MSG_END = __MSG_ESC + b'\x0f'
  __MSG_ACK = __MSG_ESC + b'\xf3'

  __PATTERN = re.compile(
    # b'(?P<start>%s)' % __MSG_START +
    __MSG_START
    + b'(?P<cmd>\x00[%s])'
    % (b'\x02\x04\x0c\x0e\x10\x12\x14\x1a\x38\x3c\x3e\x40\x66\x68\x6a\x70\x72\x74\x98\x9c\x9e\xa2\xaa\xca\xce\xd2\xd6\xda\xde\xe0\xe2\xe6\xea\xec')
    + b'(?P<length>[\x00-\x40])'
    + b'(?P<data>(?:[^%s]|%s){0,64})' % (__MSG_ESC, __MSG_ESC * 2)
    + b'(?P<cs>(?:[^%s]|%s))' % (__MSG_ESC, __MSG_ESC * 2)
    +
    # b'(?P<end>%s)' % __MSG_END +
    __MSG_END
    + b'|'
    + b'(?P<ack>%s)' % __MSG_ACK,
    re.DOTALL,
  )

  @staticmethod
  def _checksum(buf):
    return (sum(buf) + 173) & 0xFF

  @staticmethod
  def _escape(msg):
    return msg.replace(ComfoAirBase.__MSG_ESC, ComfoAirBase.__MSG_ESC * 2)

  @staticmethod
  def _unescape(msg):
    return msg.replace(ComfoAirBase.__MSG_ESC * 2, ComfoAirBase.__MSG_ESC)

  @staticmethod
  def _ack():
    return ComfoAirBase.__MSG_ACK

  @staticmethod
  def _create_msg(cmd, data=b''):
    payload = pack('>H', cmd)
    payload += pack('B', len(data))
    payload += ComfoAirBase._escape(data)
    checksum = ComfoAirBase._checksum(payload)
    payload += ComfoAirBase._escape(pack('B', checksum))
    return ComfoAirBase.__MSG_START + payload + ComfoAirBase.__MSG_END

  @staticmethod
  def _parse_msg(buf):
    start = 0
    end = 0

    for match in ComfoAirBase.__PATTERN.finditer(buf):
      if match.start() > start:
        logger.debug('Skipped %d bytes at offset %d: [%s]', match.start() - start, start, buf[start : match.start()].hex())

      if match.group('ack'):
        return [match.end(), 'ack']

      data = ComfoAirBase._unescape(match.group('data'))
      length = match.group('length')[0]
      if len(data) == length:
        checksum = ComfoAirBase._unescape(match.group('cs'))[0]
        payload = match.group('cmd') + match.group('length') + data
        if ComfoAirBase._checksum(payload) == checksum:
          cmd = int.from_bytes(match.group('cmd'), 'big')
          return [match.end(), 'msg', cmd, data]

      if len(data) < length and len(buf) - match.start() < (length * 2) + 8:
        break

      logger.debug('Cannot parse %d bytes at offset %d: [%s]', len(match.group(0)), match.start(), match.group(0).hex())

      start = match.start()
      # assert match.end() > end
      end = match.end()

    return [end]
