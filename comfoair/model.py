import abc
import enum
import typing

import bitstring


class DataType(abc.ABC):
  @staticmethod
  @abc.abstractmethod
  def convert(value: bitstring.BitArray) -> typing.Any: ...


class StrType(DataType):
  @staticmethod
  def convert(value: bitstring.BitArray) -> str:
    return value.bytes.decode('latin1')


class IntType(DataType):
  @staticmethod
  def convert(value: bitstring.BitArray) -> int:
    return value.uint


class TempType(DataType):
  @staticmethod
  def convert(value: bitstring.BitArray) -> float:
    return (value.uint / 2) - 20


class SetFanSpeed(enum.IntEnum):
  auto = 0x0
  away = 0x1
  low = 0x2
  middle = 0x3
  high = 0x4
