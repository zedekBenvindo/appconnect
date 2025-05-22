# Conteúdo COMPLETO e ATUALIZADO para: app.py
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import jwt
import datetime
from functools import wraps
import os
import paho.mqtt.client as paho_mqtt
import threading
import time

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)

app.config['SECRET_KEY'] = 'sua_chave_secreta_super_segura_e_dificil_987$#@' # MUDE ISSO EM PRODUÇÃO!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///meu_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

MQTT_BROKER_ADDRESS = "localhost"
MQTT_BROKER_PORT = 1883
MQTT_STATE_TOPIC_WILDCARD = "devices/+/state"

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    devices = db.relationship('Device', backref='owner', lazy=True, cascade="all, delete-orphan")
    def __repr__(self): return f'<User {self.username}>'

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    status = db.Column(db.String(10), nullable=False, default='OFF')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    def __repr__(self): return f'<Device {self.id}: {self.name} ({self.status}) OwnerID: {self.user_id}>'

# Este with app.app_context() garante que as tabelas são criadas no contexto correto.
# Apague o arquivo meu_app.db se você alterar a estrutura dos modelos!
with app.app_context():
    print("INFO: Backend: Verificando e criando tabelas do BD (User e Device)...")
    db.create_all()
    print("INFO: Backend: Tabelas do BD verificadas/criadas.")

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try: token = auth_header.split(" ")[1]
            except IndexError: return jsonify({'message': 'Token mal formatado!'}), 401
        if not token: return jsonify({'message': 'Token de acesso faltando!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
            if not current_user: return jsonify({'message': 'Usuário do token não encontrado.'}), 401
        except jwt.ExpiredSignatureError: return jsonify({'message': 'Token expirou!'}), 401
        except jwt.InvalidTokenError: return jsonify({'message': 'Token inválido!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def on_connect_listener(client, userdata, flags, rc, properties=None):
    if rc == 0: print(f"[MQTT Listener Backend] Conectado (rc:{rc})."); client.subscribe(MQTT_STATE_TOPIC_WILDCARD, qos=1)
    else: print(f"[MQTT Listener Backend] Falha conectar (rc:{rc}).")
def on_subscribe_listener(client, userdata, mid, granted_qos, properties=None): print(f"[MQTT Listener Backend] Subscrito a '{MQTT_STATE_TOPIC_WILDCARD}' QoS {granted_qos[0]}.")
def on_message_listener(client, userdata, msg):
    try:
        topic_parts = msg.topic.split('/')
        if len(topic_parts) == 3 and topic_parts[0] == 'devices' and topic_parts[2] == 'state':
            try:
                device_id = int(topic_parts[1]); new_status = msg.payload.decode("utf-8").upper()
                print(f"\n[MQTT Listener Backend] Status Recebido! T: {msg.topic}, S: '{new_status}'")
                with app.app_context(): # Precisa do contexto do app para operações de DB em threads
                    device = Device.query.get(device_id)
                    if device:
                        if device.status != new_status and new_status in ["ON", "OFF"]: device.status = new_status; db.session.commit(); print(f"[MQTT Listener Backend] Status ID {device_id} -> '{new_status}' no DB.")
                        elif device.status == new_status: print(f"[MQTT Listener Backend] Status ID {device_id} já era '{new_status}'.")
                        else: print(f"[MQTT Listener Backend] Status '{new_status}' inválido.")
                    else: print(f"[MQTT Listener Backend] AVISO: ID {device_id} inexistente.")
            except ValueError: print(f"[MQTT Listener Backend] AVISO: ID no tópico não é número: {topic_parts[1]}")
            except Exception as e_db: print(f"[MQTT Listener Backend] ERRO DB ID {topic_parts[1]}: {e_db}"); db.session.rollback()
        else: print(f"[MQTT Listener Backend] Msg em tópico inesperado: {msg.topic}")
    except Exception as e: print(f"[MQTT Listener Backend] Erro geral msg status: {e}")

def mqtt_listener_thread_func():
    client_id = f"flask_listener_{os.getpid()}_{time.time()}"; listener_client = paho_mqtt.Client(paho_mqtt.CallbackAPIVersion.VERSION1, client_id=client_id)
    listener_client.on_connect = on_connect_listener; listener_client.on_subscribe = on_subscribe_listener; listener_client.on_message = on_message_listener
    print("INFO: Backend: Iniciando thread listener MQTT...");
    while True: # Loop para tentar reconectar
        try: print("[MQTT Listener Thread] Tentando conectar..."); listener_client.connect(MQTT_BROKER_ADDRESS, MQTT_BROKER_PORT, 60); listener_client.loop_forever()
        except Exception as e: print(f"[MQTT Listener Thread] Erro: {e}. Reconectando em 10s..."); time.sleep(10)

@app.route('/')
def hello_world(): return 'Backend Protegido Funcionando!'
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json();
    if not data or not data.get('username') or not data.get('password'): return jsonify({'message': 'Usuário e senha obrigatórios!'}), 400
    username = data['username']; password = data['password']
    if User.query.filter_by(username=username).first(): return jsonify({'message': 'Usuário já existe.'}), 409
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password_hash=hashed_password)
    try: db.session.add(new_user); db.session.commit(); return jsonify({'message': f'Usuário {username} registrado!'}), 201
    except Exception as e: db.session.rollback(); print(f"Erro register: {e}"); return jsonify({'message': 'Erro servidor registro'}), 500
@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json();
    if not data or not data.get('username') or not data.get('password'): return jsonify({'message': 'Usuário e senha obrigatórios!'}), 400
    username = data['username']; password = data['password']
    user = User.query.filter_by(username=username).first()
    if not user: return jsonify({'message': 'Usuário não encontrado.'}), 404
    if bcrypt.check_password_hash(user.password_hash, password):
        token_payload = {'user_id': user.id, 'username': user.username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)}
        access_token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'access_token': access_token}), 200
    else: return jsonify({'message': 'Senha incorreta.'}), 401

@app.route('/api/add_device', methods=['POST'])
@token_required
def add_device(current_user):
    data = request.get_json();
    if not data or 'name' not in data or not data['name'].strip(): return jsonify({'message': 'Nome faltando'}), 400
    try: novo_dispositivo = Device(name=data['name'].strip(), owner=current_user); db.session.add(novo_dispositivo); db.session.commit(); return jsonify({'id': novo_dispositivo.id, 'name': novo_dispositivo.name, 'status': novo_dispositivo.status}), 201
    except Exception as e: db.session.rollback(); print(f"Erro add: {e}"); return jsonify({'message': 'Erro servidor add'}), 500
@app.route('/api/devices', methods=['GET'])
@token_required
def get_devices(current_user):
    try:
        lista_dispositivos = Device.query.filter_by(user_id=current_user.id).all(); dispositivos_formatados = []
        for device in lista_dispositivos: dispositivos_formatados.append({'id': device.id, 'name': device.name, 'status': device.status})
        return jsonify(dispositivos_formatados)
    except Exception as e: print(f"Erro list: {e}"); return jsonify({'message': 'Erro servidor list'}), 500

@app.route('/api/device/<int:device_id>', methods=['GET', 'PUT', 'DELETE'])
@token_required
def specific_device(current_user, device_id):
    device = Device.query.filter_by(id=device_id, user_id=current_user.id).first_or_404()
    if request.method == 'GET': return jsonify({'id': device.id, 'name': device.name, 'status': device.status})
    elif request.method == 'PUT':
        data = request.get_json();
        if not data or 'name' not in data or not data['name'].strip(): return jsonify({'message': 'Novo nome faltando'}), 400
        device.name = data['name'].strip();
        try: db.session.commit(); return jsonify({'id': device.id, 'name': device.name, 'status': device.status}), 200
        except Exception as e: db.session.rollback(); print(f"Erro PUT: {e}"); return jsonify({'message': 'Erro servidor update'}), 500
    elif request.method == 'DELETE':
        try: db.session.delete(device); db.session.commit(); return jsonify({'message': f'Dispositivo ID {device_id} excluído!'}), 200
        except Exception as e: db.session.rollback(); print(f"Erro delete: {e}"); return jsonify({'message': 'Erro servidor excluir'}), 500

@app.route('/api/device/<int:device_id>/control', methods=['POST'])
@token_required
def control_device(current_user, device_id):
    device = Device.query.filter_by(id=device_id, user_id=current_user.id).first_or_404()
    data = request.get_json();
    if not data or 'action' not in data: return jsonify({'message': 'Ação faltando'}), 400
    action = str(data['action']).upper();
    if action not in ["ON", "OFF"]: return jsonify({'message': 'Ação inválida'}), 400
    topic = f"devices/{device_id}/command"; payload = action
    print(f"INFO: Backend: POST ID {device_id} (User {current_user.id}). MQTT Pub -> T: '{topic}', P: '{payload}'")
    try:
        client_id = f"flask_pub_{os.getpid()}_{device_id}_{time.time()}"; mqttc = paho_mqtt.Client(paho_mqtt.CallbackAPIVersion.VERSION1, client_id=client_id)
        mqttc.connect(MQTT_BROKER_ADDRESS, MQTT_BROKER_PORT, 60); mqttc.loop_start()
        publish_info = mqttc.publish(topic, payload=payload, qos=1); publish_info.wait_for_publish(timeout=5); mqttc.loop_stop(); mqttc.disconnect()
        if publish_info.is_published():
            print(f"INFO: Backend: MQTT pub OK '{topic}'. Aguardando status DB..."); time.sleep(1.0)
            updated_device = Device.query.get(device_id)
            if updated_device: return jsonify({'id': updated_device.id, 'name': updated_device.name, 'status': updated_device.status}), 200
            else: return jsonify({'message': f'Comando enviado, mas ID {device_id} não encontrado pós-update.'}), 404
        else: print(f"AVISO: Backend: MQTT pub confirm fail '{topic}'."); return jsonify({'message': f'Comando {action} enviado, confirm fail.'}), 202
    except Exception as e: print(f"ERRO: Backend MQTT: {e}"); return jsonify({'message': f'Erro MQTT: {e}'}), 500

if __name__ == '__main__':
    if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        print("INFO: Backend: Criando e iniciando thread listener MQTT..."); listener_thread = threading.Thread(target=mqtt_listener_thread_func, daemon=True); listener_thread.start(); print("INFO: Backend: Thread listener MQTT iniciada.")
    print("INFO: Backend: Iniciando servidor Flask..."); app.run(host='0.0.0.0', debug=True, use_reloader=False)