from typing import Type, TypeVar

from base64 import b64decode

from lib.proto.cloud import (
    AnalysisResponse,
    AppInfo,
    CleanParamRequest,
    ModeCtrlRequest,
    StationResponse,
    WorkStatus,
)
from betterproto import Message

DP_MAP: dict[int, Type[Message]] = {
    152: ModeCtrlRequest,
    153: WorkStatus,
    154: CleanParamRequest,
    169: AppInfo,
    173: StationResponse,
    179: AnalysisResponse,
}


T = TypeVar("T", bound=Message)


def decode(b64_data: str, to_type: Type[T], has_length: bool = True) -> T:
    data = b64decode(b64_data)

    if has_length:
        data = data[1:]

    return to_type().FromString(data)


def encode(data: Message, has_length: bool = True) -> bytes:
    out = data.SerializeToString()

    if has_length:
        out = bytes([len(out)]) + out

    return out
