# Generated by the protocol buffer compiler.  DO NOT EDIT!
# sources: proto/cloud/p2pdata.proto
# plugin: python-betterproto
# This file has been @generated

from dataclasses import dataclass
from typing import List

import betterproto

from ... import cloud as __cloud__
from .. import stream as _stream__


class MapChannelMsgMsgType(betterproto.Enum):
    MAP_INFO = 0
    MULTI_MAP_RESPONSE = 1


class MapInfoMapMsgType(betterproto.Enum):
    MAP_REALTIME = 0
    MAP_ROOMOUTLINE = 1
    OBSTACLE_INFO = 2
    RESTRICT_ZONES = 3
    ROOM_PARAMS = 4
    CRUISE_DATA = 5
    TEMPORARY_DATA = 6


class CompletePathType(betterproto.Enum):
    SWEEP = 0
    MOP = 1
    SWEEP_MOP = 2
    NAVI = 3
    GOHOME = 4


class CompletePathState(betterproto.Enum):
    FOLLOW = 0
    NEW = 1


@dataclass(eq=False, repr=False)
class MapChannelMsg(betterproto.Message):
    """
    *
     地图数据的统一入口, 包括实时地图数据, 多地图相关数据.
    """

    type: "MapChannelMsgMsgType" = betterproto.enum_field(1)
    map_info: "MapInfo" = betterproto.message_field(2, group="MsgData")
    """实时地图数据不需要发送请求(为实时推送)"""

    multi_map_response: bytes = betterproto.bytes_field(3, group="MsgData")
    """该成员解析为MultiMapsManageResponse类型, 需要发送相应DP请求."""


@dataclass(eq=False, repr=False)
class MapPixels(betterproto.Message):
    """
    *
     房间轮廓信息（使用包含分区信息的地图），单次上传.

     @note: Delimited 方式序列化.
    """

    pixels: bytes = betterproto.bytes_field(1)
    """
    *
     地图像素数据，目前采用 LZ4 压缩;
     地图更新采用SLAM地图+分区地图的方式维护，slam地图实时更新，分区地图仅在保存地图、用户手动调整分区时更新；
     实时地图:
          1byte表示4像素，即1个像素2bit:
              0x00 为未知区域
              0x01 为张障碍物
              0x02 为可清扫区域
              0x03 为地毯
     分区地图：
          1byte表示1像素的方式
              低2bit表示像素
                  0x00 为未知区域
                  0x01 为张障碍物
                  0x02 为可清扫区域
                  0x03 为地毯
              高6bit表示房间分区id
                  每个像素占 1byte，包含房间id、是否是背景等数据.
                  房间标识说明
                      有效房间标识: 0 - 31
                      无效房间标识: 大于等于32
                  特殊房间标识：
                      60：没有房间数据
                      61：房间间隙
                      62：代表障碍物
                      63：未知的房间标识
    """

    pixel_size: int = betterproto.uint32_field(2)
    """
    *
     地图像素原始size, 如果pixels有压缩，则 pixel_size 表示解压后的长度.
    """


@dataclass(eq=False, repr=False)
class MapInfo(betterproto.Message):
    """
    *
    p2p数据相当于直播，不会在云端保存，每次可以直接传输全量数据
    """

    releases: int = betterproto.uint32_field(1)
    map_id: int = betterproto.uint32_field(2)
    map_stable: bool = betterproto.bool_field(3)
    map_width: int = betterproto.uint32_field(4)
    map_height: int = betterproto.uint32_field(5)
    origin: "__cloud__.Point" = betterproto.message_field(6)
    docks: List["__cloud__.Pose"] = betterproto.message_field(7)
    msg_type: "MapInfoMapMsgType" = betterproto.enum_field(8)
    pixels: "MapPixels" = betterproto.message_field(9, group="MapMsg")
    obstacles: "_stream__.ObstacleInfo" = betterproto.message_field(10, group="MapMsg")
    restricted_zones: "_stream__.RestrictedZone" = betterproto.message_field(
        11, group="MapMsg"
    )
    room_params: "_stream__.RoomParams" = betterproto.message_field(12, group="MapMsg")
    cruise_data: "_stream__.CruiseData" = betterproto.message_field(13, group="MapMsg")
    temporary_data: "_stream__.TemporaryData" = betterproto.message_field(
        14, group="MapMsg"
    )
    is_new_map: int = betterproto.uint32_field(15)
    name: str = betterproto.string_field(16)


@dataclass(eq=False, repr=False)
class CompleteMap(betterproto.Message):
    releases: int = betterproto.uint32_field(1)
    map_id: int = betterproto.uint32_field(2)
    map_stable: bool = betterproto.bool_field(3)
    map_width: int = betterproto.uint32_field(4)
    map_height: int = betterproto.uint32_field(5)
    origin: "__cloud__.Point" = betterproto.message_field(6)
    docks: List["__cloud__.Pose"] = betterproto.message_field(7)
    map: "MapPixels" = betterproto.message_field(8)
    room_outline: "MapPixels" = betterproto.message_field(9)
    obstacles: "_stream__.ObstacleInfo" = betterproto.message_field(10)
    restricted_zones: "_stream__.RestrictedZone" = betterproto.message_field(11)
    room_params: "_stream__.RoomParams" = betterproto.message_field(12)
    temporary_data: "_stream__.TemporaryData" = betterproto.message_field(13)
    is_new_map: int = betterproto.uint32_field(14)
    name: str = betterproto.string_field(15)


@dataclass(eq=False, repr=False)
class CompletePath(betterproto.Message):
    """
    *
    一个路径点包含 5 个字节:
    byte 1-2:  x 坐标, byte1高字节，最高位为符号位, byte2为低字节;
    byte 3-4:  y 坐标，byte3高字节，最高位为符号位, byte4为低字节;
    byte 5:    flags信息，
    bit 0-3 类型，0 - 清扫，1 - 拖地，2 - 扫+拖，3 - 导航，4 - 回充 (TODO: 根据需求完善)
    bit 4: 状态，0 - 继续上一轨迹点， 1 - 新轨迹点，与上一轨迹点不连续；
    """

    path: bytes = betterproto.bytes_field(3)
    path_lz4_len: int = betterproto.uint32_field(4)
