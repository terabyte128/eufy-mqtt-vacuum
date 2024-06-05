# Generated by the protocol buffer compiler.  DO NOT EDIT!
# sources: proto/cloud/alarm.proto
# plugin: python-betterproto
from dataclasses import dataclass

import betterproto


@dataclass
class Alarm(betterproto.Message):
    hours: int = betterproto.uint32_field(1)
    minutes: int = betterproto.uint32_field(2)
    repetiton: bool = betterproto.bool_field(3)
    week_info: int = betterproto.uint32_field(4)


@dataclass
class SyncTime(betterproto.Message):
    year: int = betterproto.uint32_field(1)
    month: int = betterproto.uint32_field(2)
    day: int = betterproto.uint32_field(3)
    weekday: int = betterproto.uint32_field(4)
    hours: int = betterproto.uint32_field(5)
    minutes: int = betterproto.uint32_field(6)
    seconds: int = betterproto.uint32_field(7)
