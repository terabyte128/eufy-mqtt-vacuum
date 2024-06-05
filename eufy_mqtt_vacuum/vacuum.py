import httpx
from eufy_mqtt_vacuum.decoder import decode, DP_MAP
import json
from tempfile import NamedTemporaryFile
import paho.mqtt.client as mqtt
import paho.mqtt.enums as mqtt_enums
from functools import cached_property
import hashlib
from time import time

from pydantic import BaseModel


class Authentication(BaseModel):
    user_id: str
    access_token: str
    refresh_token: str
    expires_at: int


class Device(BaseModel):
    id: str
    model: str
    product_code: str
    name: str


class UserCenterInfo(BaseModel):
    token: str
    id: str

    @property
    def gtoken(self) -> str:
        hash = hashlib.md5(self.id.encode())
        return hash.hexdigest()


class MqttConnectionInfo(BaseModel):
    endpoint_addr: str
    user_id: str
    app_name: str
    thing_name: str
    certificate_pem: str
    private_key: str
    aws_root_ca1_pem: str
    vacuum_model: str = "T2351"
    vacuum_sn: str

    @property
    def client_id(self):
        return f"android-{self.app_name}-{self.user_id}-eufy_android_Android SDK built for arm64_{self.user_id}"

    @property
    def username(self):
        return self.thing_name

    def make_client(self) -> mqtt.Client:
        mqtt_client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2, client_id=self.client_id
        )
        mqtt_client.username = self.thing_name

        with (
            NamedTemporaryFile("w") as client_cert,
            NamedTemporaryFile("w") as client_key,
            NamedTemporaryFile("w") as root_ca,
        ):
            client_cert.write(self.certificate_pem)
            client_key.write(self.private_key)
            root_ca.write(self.aws_root_ca1_pem)

            client_cert.flush()
            client_key.flush()
            root_ca.flush()

            mqtt_client.tls_set(
                ca_certs=root_ca.name,
                certfile=client_cert.name,
                keyfile=client_key.name,
            )

        @mqtt_client.connect_callback()
        def on_connect(client, userdata, flags, reason_code, properties):
            print("connected", client, userdata, flags, reason_code, properties)
            mqtt_client.subscribe(
                f"cmd/eufy_home/{self.vacuum_model}/{self.vacuum_sn}/#"
            )

        @mqtt_client.disconnect_callback()
        def on_disconnect(client, userdata, disconnect_flags, reason_code, properties):
            print(
                "disconnected",
                client,
                userdata,
                disconnect_flags,
                reason_code,
                properties,
            )

        @mqtt_client.message_callback()
        def on_message(client, userdata, msg):
            decoded_msg = json.loads(msg.payload)

            client_id = decoded_msg["head"]["client_id"]
            message_data = decoded_msg["payload"]

            if isinstance(message_data, str):
                message_data = json.loads(message_data)

            data = message_data["data"]

            print("-----------------")
            print(client_id)

            for dp, encoded in data.items():
                dp = int(dp)
                if dp not in DP_MAP:
                    print("skipping unknown dp", dp, encoded)
                    continue

                decoded = decode(encoded, DP_MAP[dp])
                print(decoded)

            print("-----------------")

        err = mqtt_client.connect(self.endpoint_addr, port=8883)
        if err != mqtt_enums.MQTTErrorCode.MQTT_ERR_SUCCESS:
            raise Exception(f"failed to connect: {err}")

        mqtt_client.loop_forever()

        return mqtt_client


class EufyClient:
    def __init__(self, username: str, password: str, vacuum_sn: str):
        self.username = username
        self.password = password
        self.vacuum_sn = vacuum_sn
        self._auth: Authentication | None = None

    @property
    def auth(self) -> Authentication:
        if self._auth is None or self._auth.expires_at < int(time()) + 15:
            self._auth = self._eufy_login()

        return self._auth

    def _eufy_login(self) -> Authentication:
        rsp = httpx.post(
            "https://home-api.eufylife.com/v1/user/email/login",
            json={
                "email": self.username,
                "password": self.password,
                "client_id": "eufyhome-app",
                "client_secret": "GQCpr9dSp3uQpsOMgJ4xQ",
            },
        )
        rsp.raise_for_status()
        data = rsp.json()

        return Authentication(
            user_id=data["user_id"],
            access_token=data["access_token"],
            refresh_token=data["refresh_token"],
            expires_at=int(time()) + data["expires_in"],
        )

    @cached_property
    def devices(self) -> list[Device]:
        rsp = httpx.get(
            "https://api.eufylife.com/v1/device/v2",
            headers={
                "category": "Home",
                "token": self.auth.access_token,
            },
        )
        rsp.raise_for_status()
        data = rsp.json()

        return [
            Device(
                id=dev["id"],
                model=dev["name"],
                name=dev["alias_name"],
                product_code=dev["product"]["product_code"],
            )
            for dev in data["devices"]
        ]

    @cached_property
    def user_center(self) -> UserCenterInfo:
        rsp = httpx.get(
            "https://api.eufylife.com/v1/user/user_center_info",
            headers={
                "token": self.auth.access_token,
            },
        )
        rsp.raise_for_status()
        data = rsp.json()

        return UserCenterInfo(
            id=data["user_center_id"], token=data["user_center_token"]
        )

    @cached_property
    def mqtt_connection(self) -> MqttConnectionInfo:
        rsp = httpx.post(
            "https://aiot-clean-api-pr.eufylife.com/app/devicemanage/get_user_mqtt_info",
            headers={
                "app-name": "eufy_home",
                "model-type": "PHONE",
                "x-auth-token": self.user_center.token,
                "gtoken": self.user_center.gtoken,
            },
        )
        rsp.raise_for_status()
        data = rsp.json()["data"]

        return MqttConnectionInfo(**data, vacuum_sn=self.vacuum_sn)
