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

import asyncio
import logging
import socket
import typing
from datetime import datetime
from struct import pack
from urllib.parse import urlparse

from async_timeout import timeout
from bitstring import BitArray
from serial import SerialException
from serial_asyncio_fast import create_serial_connection

import comfoair
import comfoair.model

from . import ComfoAirBase

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class CACommand(asyncio.Event):
  def __init__(self, cmd: int, data: bytes | None = None):
    super().__init__()
    self._cmd = cmd
    self._data = data

  @property
  def cmd(self) -> int:
    return self._cmd

  @property
  def data(self) -> bytes | None:
    return self._data


class CACommandPair:
  def __init__(self, tx: CACommand, rx: CACommand = None):
    self._tx = tx
    self._rx = rx

  @property
  def tx(self) -> CACommand:
    return self._tx

  @property
  def rx(self) -> CACommand | None:
    return self._rx


class ComfoAir(ComfoAirBase, asyncio.Protocol):
  def __init__(self, url, *args, **kwargs):
    super().__init__(*args, **kwargs)
    self._url = urlparse(url)
    self._transport = None
    self._cooked_listeners: dict[comfoair.CAReponse, set[typing.Callable[[comfoair.CAReponse, typing.Any], typing.Awaitable[None]]]] = {}
    self._cooked_cache = {}
    self._raw_listeners = set()
    self._raw_attr_event_listener = set()
    self._raw_cache = {}
    self._rx_queue = None
    self._rx_task = None
    self._tx_queue = None
    self._tx_task = None
    self._running = False
    self._buf = b''
    self._cmd = None
    self._lock = None

  @property
  def running(self) -> bool:
    return self._running

  def _geturl(self):
    return self._url.geturl()

  async def _resume_reading(self, delay):
    await asyncio.sleep(delay)
    if self._transport:
      self._transport.resume_reading()

  def _delay_reading(self, delay):
    self._transport.pause_reading()
    asyncio.ensure_future(self._resume_reading(delay))

  def data_received(self, data: bytes):
    self._rx_queue.put_nowait(data)
    self._delay_reading(1)

  def connection_lost(self, exc: Exception | None):
    logger.warning('Lost connection to %s: %s', self._geturl(), exc)
    if self._running and not self._lock.locked():
      asyncio.ensure_future(
        self._reconnect(delay=10),
      )

  def device_id(self):
    if self._url.scheme == 'socket':
      return f'{self._url.hostname}:{self._url.port}'
    return f'{socket.gethostname()}:{self._geturl().split("/")[-1]}'

  @staticmethod
  def _flush_queue(queue):
    while not queue.empty():
      queue.get_nowait()

    while True:
      try:
        queue.task_done()
      except ValueError:
        break

  async def _create_connection(self):
    loop = asyncio.get_running_loop()
    if self._url.scheme == 'socket':
      kwargs = {
        'host': self._url.hostname,
        'port': self._url.port,
      }
      return await loop.create_connection(lambda: self, **kwargs)

    kwargs = {
      'url': self._geturl(),
      'baudrate': self._BAUD_RATE,
    }
    return await create_serial_connection(loop, lambda: self, **kwargs)

  async def _reconnect(self, delay: int = 0):
    async with self._lock:
      await self._disconnect()
      self._flush_queue(self._rx_queue)

      await asyncio.sleep(delay)

      logger.info('Connecting to %s', self._geturl())
      try:
        async with timeout(5):
          self._transport, _ = await self._create_connection()
      except (TimeoutError, BrokenPipeError, ConnectionRefusedError, SerialException) as exc:
        logger.warning(exc)
        asyncio.ensure_future(
          self._reconnect(delay=10),
        )
      else:
        logger.info('Connected to %s', self._geturl())

  def _write(self, msg):
    if not self._transport:
      logger.warning('Transport unavailable!')
      return False

    self._transport.write(msg)
    return True

  async def _tx_worker(self):
    while self._running:
      self._cmd = await self._tx_queue.get()
      msg = self._create_msg(self._cmd.tx.cmd, self._cmd.tx.data)

      for tries in range(10):
        self._cmd.tx.clear()

        logger.debug('Write #%d %#x %s', tries + 1, self._cmd.tx.cmd, self._cmd.tx.data.hex())

        if not self._write(msg):
          break

        try:
          async with timeout(1):
            await self._cmd.tx.wait()
        except TimeoutError:
          logger.warning('TX ack timeout')
          continue

        logger.debug('ACK ok')
        if self._cmd.rx is None:
          break

        try:
          async with timeout(1):
            await self._cmd.rx.wait()
        except TimeoutError:
          logger.warning('RX msg timeout')
          continue

        logger.debug('message ok (bufsize=%d)', len(self._buf))
        self._write(self._ack())
        break

      self._tx_queue.task_done()
      self._cmd = None

  async def _transaction(self, cmd: CACommandPair) -> None:
    await self._tx_queue.put(cmd)

  async def _attr_listener_cmd(self, cmd, data):
    if not self._raw_attr_event_listener:
      return

    array = BitArray(data)

    if cmd in comfoair.RESPONSES:
      for attr in comfoair.RESPONSES[cmd]:
        offset = attr.offset * 8
        bits = array[offset : offset + (attr.size * 8)]
        value = attr.data_type.convert(bits)

        for callback in self._raw_attr_event_listener:
          await callback(attr, value)

  async def _cook_cmd(self, cmd, data):
    if not self._cooked_listeners:
      return

    # if self._raw_cache.get(cmd) == data:
    #     return
    self._raw_cache[cmd] = data
    array = BitArray(data)

    for attr, callbacks in self._cooked_listeners.items():
      if attr.cmd == cmd:
        offset = attr.offset * 8
        bits = array[offset : offset + (attr.size * 8)]
        value = attr.data_type.convert(bits)

        # if self._cooked_cache.get(attr) == value:
        #     continue
        self._cooked_cache[attr] = value

        for callback in callbacks:
          await callback(attr, value)

  async def _process_data(self):
    res = self._parse_msg(self._buf)
    end = res.pop(0)
    self._buf = self._buf[end:]

    if not res:
      if len(self._buf) >= (65 * 2 + 7) * 2 and not end:
        logger.debug('%d unparsable bytes to go from %s.', len(self._buf), self._geturl())
        self._buf = b''
        asyncio.ensure_future(
          self._reconnect(delay=3),
        )
      return False

    msg_type = res.pop(0)
    if self._cmd:
      if self._cmd.tx and msg_type == 'ack':
        logger.debug('Read ack')
        self._cmd.tx.set()

      elif self._cmd.rx and msg_type == 'msg':
        logger.debug('Read %#x %s', res[0], res[1].hex())
        if self._cmd.rx.cmd == res[0] and self._cmd.rx.data in (None, res[1]):
          self._cmd.rx.set()

    if msg_type == 'msg':
      for listener in self._raw_listeners:
        await listener(res)
      await self._cook_cmd(res[0], res[1])
      await self._attr_listener_cmd(res[0], res[1])

    return True

  async def _rx_worker(self):
    while self._running:
      self._buf += await self._rx_queue.get()

      while self._buf and self._running:
        more = await self._process_data()
        if not more:
          break

      self._rx_queue.task_done()

  async def connect(self):
    if self._running:
      logger.debug('Already connected!')
      return

    self._rx_queue = asyncio.Queue()
    self._rx_task = asyncio.ensure_future(self._rx_worker())
    self._tx_queue = asyncio.Queue()
    self._tx_task = asyncio.ensure_future(self._tx_worker())
    self._lock = asyncio.Lock()
    self._running = True
    await self._reconnect()

  async def _disconnect(self):
    if self._transport:
      logger.debug('Disconnecting from %s', self._geturl())
      self._transport.abort()
      self._transport = None
    self._buf = b''

  async def shutdown(self):
    async with self._lock:
      if not self._running:
        logger.debug('Already shut down!')
        return

      logger.debug('Shutting down connection to %s', self._geturl())
      self._running = False

      await self._disconnect()

      if self._rx_task:
        self._rx_task.cancel()
      if self._tx_task:
        self._tx_task.cancel()

      await asyncio.gather(self._tx_task, self._rx_task, return_exceptions=True)

  async def set_rtc(self, val: datetime):
    logger.debug('Set RTC: %s', val.ctime())

    data = pack('BBB', (val.weekday() + 2) % 7, val.hour, val.minute)
    cmd = CACommandPair(CACommand(0x35, data), CACommand(0x3C))

    await self._transaction(cmd)

  async def emulate_keypress(self, key_mask: int, millis: int):
    logger.debug('Emulate keypress: %d (%d millis)', key_mask, millis)

    if not 1 <= key_mask <= 63:
      logger.error('Invalid key mask: %d', key_mask)
      return

    duration = min(max(millis, 1), 4080) * 255 // 4080
    key_status = bytearray(b'\x00' * 7)
    for key in range(6):
      if key_mask & (1 << key):
        key_status[key] = duration

    cmd_key_status = CACommandPair(CACommand(0x37, key_status), CACommand(0x3C))
    await self._transaction(cmd_key_status)

  async def switch_to_pc_mode(self) -> None:
    logger.debug('Switch to PC mode')
    cmd = CACommandPair(CACommand(0x9B, b'\x03'), CACommand(0x9C, b'\x03'))
    await self._transaction(cmd)

  async def switch_to_cc_ease_mode(self) -> None:
    logger.debug('Switch to CC ease mode')
    cmd = CACommandPair(CACommand(0x9B, b'\x00'), CACommand(0x9C, b'\x02'))
    await self._transaction(cmd)

  async def set_speed(self, speed: comfoair.model.SetFanSpeed):
    logger.debug('Set speed: %d', speed)
    cmd_set_speed = CACommandPair(CACommand(0x99, pack('B', speed)))
    await self._transaction(cmd_set_speed)

  async def set_comfort_temperature(self, comfort_temperature: int):
    if not 15 <= comfort_temperature <= 27:
      raise ValueError(f'Invalid comfort temperature: {comfort_temperature}, must be between 15 and 27')

    logger.debug('Set comfort temperature: %d', comfort_temperature)
    cmd_set_comfort_temperature = CACommandPair(CACommand(0xD3, pack('B', comfort_temperature)))
    await self._transaction(cmd_set_comfort_temperature)

  async def request_bootloader_version(self):
    logger.debug('Request bootloader version')
    cmd = CACommandPair(CACommand(0x67, b''), CACommand(0x68))
    await self._transaction(cmd)

  async def request_firmware_version(self):
    logger.debug('Request firmware version')
    cmd = CACommandPair(CACommand(0x69, b''), CACommand(0x6A))
    await self._transaction(cmd)

  async def request_version(self):
    logger.debug('Request connector board version')
    cmd = CACommandPair(CACommand(0xA1, b''), CACommand(0xA2))
    await self._transaction(cmd)

  async def request_ventilation_status(self):
    logger.debug('Request ventilation status')
    cmd = CACommandPair(CACommand(0x0B, b''), CACommand(0x0C))
    await self._transaction(cmd)

  async def request_bypass_status(self):
    logger.debug('Request bypass status')
    cmd = CACommandPair(CACommand(0x0D, b''), CACommand(0x0E))
    await self._transaction(cmd)

  async def request_temperature_status(self):
    logger.debug('Request temperature status')
    cmd = CACommandPair(CACommand(0x0F, b''), CACommand(0x10))
    await self._transaction(cmd)

  async def request_temperatures(self):
    logger.debug('Request temperatures')
    cmd = CACommandPair(CACommand(0xD1, b''), CACommand(0xD2))
    await self._transaction(cmd)

  async def request_ventilation_set(self):
    logger.debug('Request ventilation set')
    cmd = CACommandPair(CACommand(0xCD, b''), CACommand(0xCE))
    await self._transaction(cmd)

  async def request_errors(self):
    logger.debug('Request errors')
    cmd = CACommandPair(CACommand(0xD9, b''), CACommand(0xDA))
    await self._transaction(cmd)

  async def request_running_hours(self):
    logger.debug('Request running hours')
    cmd = CACommandPair(CACommand(0xDD, b''), CACommand(0xDE))
    await self._transaction(cmd)

  def add_listener(self, listener):
    self._raw_listeners.add(listener)

  def remove_listener(self, listener):
    self._raw_listeners.discard(listener)

  def add_attr_event_listener(self, listener):
    self._raw_attr_event_listener.add(listener)

  def remove_attr_event_listener(self, listener):
    self._raw_attr_event_listener.discard(listener)

  def add_cooked_listener(self, attribute: comfoair.CAReponse, listener: typing.Callable[[comfoair.CAReponse, typing.Any], typing.Awaitable[None]]):
    if attribute not in self._cooked_listeners:
      self._cooked_listeners[attribute] = set()
    self._cooked_listeners[attribute].add(listener)
    return self._cooked_cache.get(attribute)

  def remove_cooked_listener(self, attribute: comfoair.CAReponse, listener: typing.Callable[[comfoair.CAReponse, typing.Any], typing.Awaitable[None]]):
    if attribute in self._cooked_listeners:
      self._cooked_listeners[attribute].discard(listener)
      if len(self._cooked_listeners[attribute]) == 0:
        del self._cooked_listeners[attribute]
