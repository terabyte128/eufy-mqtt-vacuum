# Generated by the protocol buffer compiler.  DO NOT EDIT!
# sources: proto/cloud/stream.proto, proto/cloud/stream_wrap.proto
# plugin: python-betterproto
from dataclasses import dataclass
from typing import List

import betterproto

from .proto import cloud


class MapInfoType(betterproto.Enum):
    INCOMPLETE = 0
    ROUGH = 1
    EFFECTIVE = 2
    LIST_FULL = 3


class MapInfoDockType(betterproto.Enum):
    ADAPTER = 0
    STATION = 1


class MapFrame(betterproto.Enum):
    I = 0
    P = 1


class MapPixelValue(betterproto.Enum):
    UNKNOW = 0
    OBSTACLE = 1
    FREE = 2
    CARPET = 3


class ObstacleInfoObstacleShowType(betterproto.Enum):
    POSITION = 0
    OUTLINE = 1
    FILL = 2
    BITMAP = 3


@dataclass
class Metadata(betterproto.Message):
    """*  通道、版本信息.   @note: Delimited 方式序列化."""

    versions: "MetadataVersions" = betterproto.message_field(1)
    chan_ids: "MetadataChanIds" = betterproto.message_field(2)


@dataclass
class MetadataVersions(betterproto.Message):
    # 只针对非 protobuf 格式的通道，protobuf协议本身是向下兼容的；
    map_data: int = betterproto.uint32_field(1)


@dataclass
class MetadataChanIds(betterproto.Message):
    # 地图信息通道，使用 message MapInfo 解析;
    map_info: int = betterproto.uint32_field(1)
    # 路径数据通道，使用 message Path 解析;
    path: int = betterproto.uint32_field(2)
    # 房间轮廓，使用 message RoomOutline 解析;
    room_outline: int = betterproto.uint32_field(3)
    # 房间参数信息，使用 message RoomParams 解析;
    room_params: int = betterproto.uint32_field(4)
    # 禁区信息，使用 message RestrictedZone 解析;
    restricted_zone: int = betterproto.uint32_field(5)
    # 动态数据，主要是位姿，使用 message DynamicData 解析;
    dynamic_data: int = betterproto.uint32_field(6)
    # 临时数据通道，包括选区、指哪到哪等参数，使用 message TemporaryData 解析;
    temporary_data: int = betterproto.uint32_field(7)
    # 视觉识别的物体信息，使用 message ObstacleInfo 解析;
    obstacle_info: int = betterproto.uint32_field(8)
    # 地图数据，使用 message Map 解析.
    map_data: int = betterproto.uint32_field(9)
    # 巡航点数据，使用 message CruiseData 解析;
    cruise_data: int = betterproto.uint32_field(10)


@dataclass
class MapInfo(betterproto.Message):
    """*  地图信息.   @note: Delimited 方式序列化."""

    map_id: int = betterproto.uint32_field(1)
    width: int = betterproto.uint32_field(2)
    height: int = betterproto.uint32_field(3)
    resolution: int = betterproto.uint32_field(4)
    origin: cloud.Point = betterproto.message_field(5)
    docks: List[cloud.Pose] = betterproto.message_field(6)
    type: "MapInfoType" = betterproto.enum_field(7)
    seq: int = betterproto.uint32_field(8)
    angle: int = betterproto.uint32_field(9)
    docks_v2: List["MapInfoDock"] = betterproto.message_field(10)


@dataclass
class MapInfoDock(betterproto.Message):
    type: "MapInfoDockType" = betterproto.enum_field(1)
    pose: cloud.Pose = betterproto.message_field(2)


@dataclass
class Map(betterproto.Message):
    """
    *  地图帧数据, 可全量和增量上传.      当 Frame 为 I 时，表示全量地图，机器端会先清除地图subid通道数据；      当
    Frame 为 P 时，表示增量地图；   @note: Delimited 方式序列化.
    """

    map_id: int = betterproto.uint32_field(1)
    seq: int = betterproto.uint32_field(2)
    frame: "MapFrame" = betterproto.enum_field(3)
    # *  地图像素数据，目前采用 LZ4 压缩;  每个像素占 2bit，即4种值，与上面 enum PixelValue 对应.
    # 像素从字节低位bit开始.
    pixels: bytes = betterproto.bytes_field(4)
    # *  地图像素原始size, 如果pixels有压缩，则 pixel_size 表示解压后的长度.
    pixel_size: int = betterproto.uint32_field(5)
    info: "MapInfo" = betterproto.message_field(6)
    name: str = betterproto.string_field(7)
    id: int = betterproto.uint32_field(8)
    releases: int = betterproto.uint32_field(9)
    index: "MapIndex" = betterproto.message_field(10)


@dataclass
class MapIndex(betterproto.Message):
    value: int = betterproto.uint32_field(1)


@dataclass
class PathPoint(betterproto.Message):
    """
    * xy 信息如下: byte 1-2:  x 坐标, byte1高字节，最高位为符号位, byte2为低字节; byte 3-4:  y
    坐标，byte3高字节，最高位为符号位, byte4为低字节; flags 信息如下: byte 1:    flags信息， bit 0-3
    类型，见下方定义： SWEEP = 0,              // 纯扫 MOP = 1,                // 纯拖地
    SWEEP_MOP = 2,          // 扫+拖地 FAST_MAPPING = 3,       // 快速建图运行轨迹
    CRUISIING = 4,          // 全屋巡航运行轨迹 POINT_TO_POINT = 5,     // 指哪到哪运行轨迹
    REMOTE_CTRL = 6,        // 遥控运行轨迹 GO_CHARGE_IN_WORK = 7,  // 任务中回充轨迹
    GO_CHARGE = 8,          // 任务结束回充轨迹 GO_WASH_IN_WORK = 9,    // 任务中回洗轨迹
    GO_WASH = 10,           // 任务结束回洗轨迹 EXPLORE_STATIONS = 11,  // 探索基站轨迹
    NAVIGATION = 12,        // 分区之间导航轨迹 RESUME_CLEANING = 13,   // 回充回洗后的续扫轨迹
    RETURN_START_POINT = 14,  // 回充失败再返回起点的轨迹 HIDE = 15,  // 隐藏轨迹（轨迹优化使用）同时需要使能
    AppFunction.optimization.PATH_HIDE_TYPE bit 4: 状态，0 - 继续上一轨迹点， 1 -
    新轨迹点，与上一轨迹点不连续； bit 5: 是否显示轨迹，0 - 不显示，1 - 显示； bit 6: 是否显示机器人，0 - 不显示，1 -
    显示； bit 7: 预留； byte 2:    task_motion_type； byte 3-4:  预留；
    """

    # bit0~15 为 x 坐标  bit16~31 为 y 坐标
    xy: int = betterproto.uint32_field(1)
    # bit0~3 为 point_type  bit4 为 break_type  bit5 为 show_trajectory_flag  bit6 为
    # show_robot_flag  bit7 预留  bit8~15 为 task_motion_type  bit16~23 预留  bit24~31
    # 预留
    flags: int = betterproto.uint32_field(2)


@dataclass
class RoomOutline(betterproto.Message):
    """*  房间轮廓信息（使用包含分区信息的地图），单次上传.   @note: Delimited 方式序列化."""

    map_id: int = betterproto.uint32_field(1)
    releases: int = betterproto.uint32_field(2)
    width: int = betterproto.uint32_field(3)
    height: int = betterproto.uint32_field(4)
    resolution: int = betterproto.uint32_field(5)
    origin: cloud.Point = betterproto.message_field(6)
    # *  地图像素数据，目前采用 LZ4 压缩;  每个像素占 1byte，表示房间 id
    pixels: bytes = betterproto.bytes_field(7)
    # *  地图像素原始size, 如果pixels有压缩，则 pixel_size 表示解压后的长度.
    pixel_size: int = betterproto.uint32_field(8)


@dataclass
class RoomParams(betterproto.Message):
    """*  房间参数，单次上传.   @note: Delimited 方式序列化."""

    # 定制化清扫参数使能.
    custom_enable: bool = betterproto.bool_field(1)
    rooms: List["RoomParamsRoom"] = betterproto.message_field(2)
    map_id: int = betterproto.uint32_field(3)
    releases: int = betterproto.uint32_field(4)
    # enum ModeType {      CUSTOM = 0;     // 通用/定制模式，x10 以后不再使用      SMART = 1;
    # // 智能模式  }  ModeType mode_type = 5;
    smart_mode_sw: cloud.Switch = betterproto.message_field(6)


@dataclass
class RoomParamsRoom(betterproto.Message):
    id: int = betterproto.uint32_field(1)
    name: str = betterproto.string_field(2)
    floor: cloud.Floor = betterproto.message_field(3)
    scene: cloud.RoomScene = betterproto.message_field(4)
    order: "RoomParamsRoomOrder" = betterproto.message_field(6)
    custom: "RoomParamsRoomCustom" = betterproto.message_field(7)


@dataclass
class RoomParamsRoomOrder(betterproto.Message):
    """定制化顺序."""

    value: int = betterproto.uint32_field(1)


@dataclass
class RoomParamsRoomCustom(betterproto.Message):
    """定制化参数."""

    clean_type: cloud.CleanType = betterproto.message_field(1)
    fan: cloud.Fan = betterproto.message_field(2)
    mop_mode: cloud.MopMode = betterproto.message_field(3)
    clean_extent: cloud.CleanExtent = betterproto.message_field(4)
    clean_times: int = betterproto.uint32_field(5)


@dataclass
class RestrictedZone(betterproto.Message):
    """*  禁区信息，单次上传.   @note: Delimited 方式序列化."""

    virtual_walls: List[cloud.Line] = betterproto.message_field(1)
    forbidden_zones: List[cloud.Quadrangle] = betterproto.message_field(2)
    ban_mop_zones: List[cloud.Quadrangle] = betterproto.message_field(3)
    map_id: int = betterproto.uint32_field(4)
    releases: int = betterproto.uint32_field(5)
    suggestion: "RestrictedZoneSuggestion" = betterproto.message_field(7)


@dataclass
class RestrictedZoneSuggestion(betterproto.Message):
    """
    自动推荐，只有推荐的禁区有 id 信息，由机器端生成，逐渐增加  机器要做到：  1.
    存在推荐禁区后，再收到一次编辑禁区消息，需要删除推荐禁区，将设置的推荐禁区转为编辑禁区  2.
    推荐的禁区没有被设置，那么机器后面就不应该再推荐这个禁区
    """

    virtual_walls: List["RestrictedZoneSuggestionLineWrap"] = betterproto.message_field(
        1
    )
    forbidden_zones: List["RestrictedZoneSuggestionQuadrangleWrap"] = (
        betterproto.message_field(2)
    )
    ban_mop_zones: List["RestrictedZoneSuggestionQuadrangleWrap"] = (
        betterproto.message_field(3)
    )


@dataclass
class RestrictedZoneSuggestionLineWrap(betterproto.Message):
    id: int = betterproto.uint32_field(1)
    line: cloud.Line = betterproto.message_field(2)


@dataclass
class RestrictedZoneSuggestionQuadrangleWrap(betterproto.Message):
    id: int = betterproto.uint32_field(1)
    quadrangle: cloud.Quadrangle = betterproto.message_field(2)


@dataclass
class DynamicData(betterproto.Message):
    """*  动态数据，单次上传.   @note: Delimited 方式序列化."""

    cur_pose: cloud.Pose = betterproto.message_field(1)


@dataclass
class TemporaryData(betterproto.Message):
    """
    *  存储临时数据，机器端不主动清除，app根据workstatus自行判断数据是否有效.  单次上传.   @note: Delimited
    方式序列化.
    """

    select_rooms_clean: cloud.SelectRoomsClean = betterproto.message_field(1)
    select_zones_clean: cloud.SelectZonesClean = betterproto.message_field(2)
    goto_location: cloud.Goto = betterproto.message_field(3)
    select_point_cruise: cloud.PointCruise = betterproto.message_field(4)
    select_zones_cruise: cloud.ZonesCruise = betterproto.message_field(5)


@dataclass
class ObstacleInfo(betterproto.Message):
    """*  物体数据信息，单次上传.   @note: Delimited 方式序列化."""

    map_id: int = betterproto.uint32_field(1)
    releases: int = betterproto.uint32_field(2)
    obstacles: List["ObstacleInfoObstacle"] = betterproto.message_field(3)


@dataclass
class ObstacleInfoObstacle(betterproto.Message):
    object_type: str = betterproto.string_field(1)
    show_type: "ObstacleInfoObstacleShowType" = betterproto.enum_field(2)
    show_points: List[cloud.Point] = betterproto.message_field(3)
    bitmap: "ObstacleInfoObstacleBitmap" = betterproto.message_field(4)
    theta: int = betterproto.sint32_field(5)
    photo_id: str = betterproto.string_field(6)
    accuracy: int = betterproto.uint32_field(7)
    valid: "ObstacleInfoObstacleValid" = betterproto.message_field(8)


@dataclass
class ObstacleInfoObstacleBitmap(betterproto.Message):
    ref_point: cloud.Point = betterproto.message_field(1)
    width: int = betterproto.uint32_field(2)
    height: int = betterproto.uint32_field(3)
    data_len: int = betterproto.uint32_field(4)
    data: bytes = betterproto.bytes_field(5)


@dataclass
class ObstacleInfoObstacleValid(betterproto.Message):
    value: bool = betterproto.bool_field(1)


@dataclass
class CruiseData(betterproto.Message):
    """
    *  巡航数据.  更新频率：巡航指令后更新一次（照片 id 为空），结束巡航后更新一次（一次性写入照片 id）   @note: Delimited
    方式序列化.
    """

    cruise_data: List["CruiseDataProcessData"] = betterproto.message_field(1)
    map_id: int = betterproto.uint32_field(2)
    releases: int = betterproto.uint32_field(3)


@dataclass
class CruiseDataProcessData(betterproto.Message):
    points: cloud.Point = betterproto.message_field(1)
    photo_id: List[str] = betterproto.string_field(2)


@dataclass
class MapDescription(betterproto.Message):
    """*  地图描述，单次上传.   @note: Delimited 方式序列化."""

    name: str = betterproto.string_field(2)
    create_cause: int = betterproto.uint32_field(3)
    create_time: int = betterproto.uint64_field(4)
    last_time: int = betterproto.uint64_field(5)
    map_id: int = betterproto.uint32_field(6)
    releases: int = betterproto.uint32_field(7)


@dataclass
class MapBackup(betterproto.Message):
    """*  地图备份，单次上传.   @note: Delimited 方式序列化."""

    desc: "MapDescription" = betterproto.message_field(1)
    map: "Map" = betterproto.message_field(2)
    rooms: "RoomOutline" = betterproto.message_field(3)
    room_params: "RoomParams" = betterproto.message_field(4)
    restricted_zone: "RestrictedZone" = betterproto.message_field(5)


@dataclass
class SceneWrap(betterproto.Message):
    """*  场景信息，单次上传.   @note: Delimited 方式序列化."""

    scenes: List["SceneWrapScene"] = betterproto.message_field(1)


@dataclass
class SceneWrapScene(betterproto.Message):
    info: cloud.SceneInfo = betterproto.message_field(1)
    tasks: List[cloud.SceneTask] = betterproto.message_field(2)


@dataclass
class RoomParamsWrap(betterproto.Message):
    room_params: List["RoomParams"] = betterproto.message_field(1)


@dataclass
class ObstacleInfoWrap(betterproto.Message):
    obstacle_info: List["ObstacleInfo"] = betterproto.message_field(1)
