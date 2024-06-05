from eufy_mqtt_vacuum.vacuum import EufyClient

c = EufyClient("<username>", "<password>", "<vacuum serial number>")
mqttc = c.mqtt_connection

mqttc.make_client()
