# Eufy MQTT Client

Create virtual environment:

```shell
$ virtualenv venv
$ source venv/bin/activate
$ pip sync requirements.txt
```

Update your Eufy username and password in `main.py`

To regenerate protobuf files:

```shell
$ protoc -I . --python_betterproto_out=lib proto/cloud/*.proto
```
