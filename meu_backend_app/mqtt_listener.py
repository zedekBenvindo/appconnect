# Conteúdo para: C:\Projects\zdk_APP\meu_backend_app\mqtt_listener.py
import paho.mqtt.client as paho_mqtt
import time
import sys

MQTT_BROKER_ADDRESS = "localhost"; MQTT_BROKER_PORT = 1883
COMMAND_TOPIC_WILDCARD = "devices/+/command"; STATE_TOPIC_BASE = "devices"

def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0: print(f"[Listener Script] Conectado Broker (rc:{rc})."); client.subscribe(COMMAND_TOPIC_WILDCARD, qos=1)
    else: print(f"[Listener Script] Falha conectar (rc:{rc})."); sys.exit(1)
def on_subscribe(client, userdata, mid, granted_qos, properties=None): print(f"[Listener Script] Subscrito a '{COMMAND_TOPIC_WILDCARD}' QoS {granted_qos[0]}. Aguardando...")
def on_message(client, userdata, msg):
    try:
        topic_parts = msg.topic.split('/');
        if len(topic_parts) == 3 and topic_parts[0] == 'devices' and topic_parts[2] == 'command':
            device_id = topic_parts[1]; command = msg.payload.decode("utf-8").upper()
            print(f"\n[Listener Script] Comando Recebido! T: {msg.topic}, C: '{command}'")
            if command in ["ON", "OFF"]:
                new_state = command; state_topic = f"{STATE_TOPIC_BASE}/{device_id}/state"
                print(f"[Listener Script] Publicando status '{new_state}' para T: '{state_topic}' (QoS 0)...")
                client.publish(state_topic, payload=new_state, qos=0, retain=True)
                print(f"[Listener Script] Status '{new_state}' publicado (QoS 0) para '{state_topic}'.")
            else: print(f"[Listener Script] Comando '{command}' desconhecido.")
        else: print(f"[Listener Script] Msg em tópico inesperado: {msg.topic}")
    except Exception as e: print(f"[Listener Script] Erro processando msg: {e}")

listener_client = paho_mqtt.Client(paho_mqtt.CallbackAPIVersion.VERSION1, client_id=f"device_listener_fresh_final_{time.time()}")
listener_client.on_connect = on_connect; listener_client.on_subscribe = on_subscribe; listener_client.on_message = on_message
print("[Listener Script] Tentando conectar ao Broker MQTT...")
try: listener_client.connect(MQTT_BROKER_ADDRESS, MQTT_BROKER_PORT, 60)
except Exception as e: print(f"[Listener Script] ERRO CRÍTICO conectar: {e}."); sys.exit(1)
print("[Listener Script] Iniciando loop..."); listener_client.loop_forever()