# Conteúdo COMPLETO e CORRIGIDO para: app.py (com OAuth e todas as funções completas)
from flask import (
    Flask, request, jsonify, render_template, session,
    redirect, url_for, g
)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import jwt
import datetime
from functools import wraps
import os
import paho.mqtt.client as paho_mqtt
import threading
import time

# Authlib imports
from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.integrations.sqla_oauth2 import (
    OAuth2ClientMixin,
    OAuth2AuthorizationCodeMixin,
    OAuth2TokenMixin,
    create_query_client_func,
    create_save_token_func 
)
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as AuthlibAuthorizationCodeGrant,
    RefreshTokenGrant as AuthlibRefreshTokenGrant,
)

# --- Setup Inicial ---
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)

# --- Configurações do App ---
app.config['SECRET_KEY'] = 'sua_chave_secreta_super_segura_e_dificil_987$#@_OAuth_FINAL' # MUDE ISSO EM PRODUÇÃO!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///meu_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = False 
app.config['SESSION_COOKIE_SAMESITE'] = "Lax"

# --- Configuração MQTT ---
MQTT_BROKER_ADDRESS = "localhost"
MQTT_BROKER_PORT = 1883
MQTT_STATE_TOPIC_WILDCARD = "devices/+/state"

# --- Inicialização das Extensões ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# --- Modelos de Banco de Dados ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    devices = db.relationship('Device', backref='owner', lazy=True, cascade="all, delete-orphan")
    oauth_clients = db.relationship('OAuth2Client', backref='user', lazy='dynamic') #user aqui é o dono do cliente OAuth
    def __repr__(self): return f'<User {self.username}>'

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    status = db.Column(db.String(10), nullable=False, default='OFF')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    def __repr__(self): return f'<Device {self.id}: {self.name} ({self.status}) OwnerID: {self.user_id}>'

class OAuth2Client(db.Model, OAuth2ClientMixin):
    __tablename__ = 'oauth2_client'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    client_id = db.Column(db.String(48), index=True)
    client_secret = db.Column(db.String(120))
    client_name = db.Column(db.String(120)) # Adicionado para metadados
    # _client_metadata = db.Column(db.Text) # Nome que Authlib espera para o JSON dos metadados

    # Adicionando os campos que set_client_metadata vai popular no JSON, para clareza
    # Estes não são colunas diretas se você está usando client_metadata JSON,
    # mas são chaves importantes dentro do JSON de client_metadata.
    # Para simplificar com create_all, vamos torná-los colunas também, se não usar _client_metadata JSON
    redirect_uris = db.Column(db.Text) # Authlib vai ler do JSON de client_metadata
    default_redirect_uri = db.Column(db.Text)
    scope = db.Column(db.Text)
    grant_types = db.Column(db.Text)
    response_types = db.Column(db.Text)
    token_endpoint_auth_method = db.Column(db.String(120))

    def __repr__(self): return f'<OAuth2Client {self.client_name}>'

class OAuth2AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
    __tablename__ = 'oauth2_authorization_code'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')
    code = db.Column(db.String(120), unique=True, nullable=False) # Adicionado para db.create_all
    client_id = db.Column(db.String(48)) # Adicionado
    redirect_uri = db.Column(db.Text) # Adicionado
    response_type = db.Column(db.Text) # Adicionado
    scope = db.Column(db.Text) # Adicionado
    auth_time = db.Column(db.Integer, nullable=False, default=lambda: int(time.time())) # Adicionado
    # nonce = db.Column(db.String(120)) # Para OpenID

class OAuth2Token(db.Model, OAuth2TokenMixin):
    __tablename__ = 'oauth2_token'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')
    client_id = db.Column(db.String(48))
    token_type = db.Column(db.String(40))
    access_token = db.Column(db.String(255), unique=True, nullable=False)
    refresh_token = db.Column(db.String(255), index=True)
    scope = db.Column(db.Text)
    issued_at = db.Column(db.Integer, nullable=False, default=lambda: int(time.time()))
    expires_in = db.Column(db.Integer, nullable=False, default=0)
    revoked = db.Column(db.Boolean, default=False)

    def is_access_token_expired(self): return self.issued_at + self.expires_in < time.time()
    def is_refresh_token_active(self): return not self.revoked # Simplificado

# --- Lógica para Sessão Web Flask ---
@app.before_request
def load_logged_in_user_from_session():
    user_id = session.get('oauth_web_user_id')
    g.user_oauth_session = User.query.get(user_id) if user_id else None

def get_current_user_for_oauth_flow(): return g.user_oauth_session if hasattr(g, 'user_oauth_session') else None

# --- Configuração Servidor OAuth 2.0 ---
def _save_oauth_token(token_data, request_obj): # Renomeado request para request_obj para evitar conflito
    # request_obj.user aqui é o usuário da SESSÃO FLASK que autorizou
    if request_obj.user:
        # Authlib >= 1.0, client_id está em request_obj.client.client_id
        client_id_val = request_obj.client.client_id

        # Remove tokens antigos (opcional mas recomendado)
        OAuth2Token.query.filter_by(user_id=request_obj.user.id, client_id=client_id_val).delete()
        
        item = OAuth2Token(
            client_id=client_id_val, user_id=request_obj.user.id,
            **token_data # Desempacota access_token, refresh_token, scope, expires_in, issued_at
        )
        db.session.add(item); db.session.commit(); return item
    return None

authorization = AuthorizationServer(app, query_client=create_query_client_func(db.session, OAuth2Client), save_token=_save_oauth_token)

class MyAuthorizationCodeGrant(AuthlibAuthorizationCodeGrant):
    def save_authorization_code(self, code, request):
        auth_code = OAuth2AuthorizationCode(code=code, client_id=request.client.client_id, redirect_uri=request.redirect_uri, scope=request.scope, user_id=request.user.id, response_type=request.response_type, auth_time=int(time.time()) )
        db.session.add(auth_code); db.session.commit(); return auth_code
    def query_authorization_code(self, code, client):
        item = OAuth2AuthorizationCode.query.filter_by(code=code, client_id=client.client_id).first()
        if item and not item.is_expired(): return item; return None
    def delete_authorization_code(self, authorization_code): db.session.delete(authorization_code); db.session.commit()
    def authenticate_user(self, authorization_code): return User.query.get(authorization_code.user_id)

authorization.register_grant(MyAuthorizationCodeGrant)
authorization.register_grant(AuthlibRefreshTokenGrant) # Usando o padrão do Authlib com nosso save_token

# --- Criação de Tabelas e Cliente OAuth de Teste ---
with app.app_context():
    print("INFO: Backend: Verificando e criando TODAS as tabelas do BD..."); db.create_all(); print("INFO: Backend: TODAS as tabelas do BD OK.")
    admin_user = User.query.filter_by(username='jessy_web').first() # Ou seu usuário de teste
    if admin_user:
        test_client = OAuth2Client.query.filter_by(client_id='alexa-skill-test-client').first()
        if not test_client:
            print("INFO: Criando cliente OAuth 'alexa-skill-test-client'...")
            redirect_uris_str = ('https://alexa.amazon.co.jp/api/skill/link/M1H1JQTEMTPHLH'
                                 ' https://pitangui.amazon.com/api/skill/link/M1H1JQTEMTPHLH'
                                 'https://layla.amazon.com/api/skill/link/M1H1JQTEMTPHLH')
            client_metadata = {
                "client_name": "Minha Skill Alexa Teste", "client_uri": "https://minha-skill.example.com",
                "grant_types": ["authorization_code", "refresh_token"], "redirect_uris": redirect_uris_str.split(),
                "response_types": ["code"], "scope": "read_devices control_devices",
                "token_endpoint_auth_method": "client_secret_post" # Alexa geralmente usa client_secret_post
            }
            # Para client_secret_post, o secret não precisa ser hasheado no DB para Authlib,
            # mas é bom para seu próprio gerenciamento. Authlib não usa o client_secret do DB para este método.
            test_client = OAuth2Client(client_id='alexa-skill-test-client', client_secret='alexa_skill_secret_123_plain', user_id=admin_user.id)
            test_client.set_client_metadata(client_metadata)
            db.session.add(test_client); db.session.commit()
            print(f"INFO: Cliente OAuth 'alexa-skill-test-client' criado/verificado. Client Secret (original): alexa_skill_secret_123_plain")
        else: print(f"INFO: Cliente OAuth 'alexa-skill-test-client' já existe.")
    else: print("AVISO: Usuário 'jessy_web' não encontrado. Registre-o para criar cliente OAuth de teste.")

# --- Decorator Token JWT API ---
def token_required(f): # Como antes
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None; auth_header = request.headers.get('Authorization')
        if auth_header:
            try: token = auth_header.split(" ")[1]
            except IndexError: return jsonify({'message': 'Token JWT mal formatado!'}), 401
        if not token: return jsonify({'message': 'Token JWT faltando!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_api_user = User.query.get(data['user_id'])
            if not current_api_user: return jsonify({'message': 'Usuário do token JWT não encontrado.'}), 401
        except Exception as e: return jsonify({'message': f'Token JWT inválido ou expirado: {str(e)}'}), 401
        return f(current_api_user, *args, **kwargs)
    return decorated

# --- MQTT Listener Interno ---
# (Funções on_connect_listener, on_subscribe_listener, on_message_listener, mqtt_listener_thread_func - COLE-AS AQUI COMPLETAS COMO NA ÚLTIMA VERSÃO FUNCIONAL)
def on_connect_listener(client, userdata, flags, rc, properties=None): # Copiado para completude
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
                with app.app_context():
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
    while True:
        try: print("[MQTT Listener Thread] Tentando conectar..."); listener_client.connect(MQTT_BROKER_ADDRESS, MQTT_BROKER_PORT, 60); listener_client.loop_forever()
        except Exception as e: print(f"[MQTT Listener Thread] Erro: {e}. Reconectando em 10s..."); time.sleep(10)

# --- Rotas ---
@app.route('/')
def hello_world(): return 'Backend Protegido Funcionando! OAuth em progresso.'

@app.route('/web/login', methods=['GET', 'POST'])
def web_login():
    user_in_session = get_current_user_for_oauth_flow(); next_url = request.args.get('next')
    if user_in_session and request.method == 'GET':
        if next_url: return redirect(next_url)
        return f"Logado como {user_in_session.username}! <a href='{url_for('web_logout')}'>Sair</a>"
    if request.method == 'POST':
        username = request.form.get('username'); password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            session.clear(); session['oauth_web_user_id'] = user.id; session.permanent = True
            print(f"Usuário ID {user.id} ({user.username}) logado na SESSÃO WEB")
            if next_url: return redirect(next_url)
            return 'Login via web OK! Pode autorizar a Skill.'
        else: return render_template('login_oauth.html', error='Usuário/senha inválidos.', next=next_url)
    return render_template('login_oauth.html', next=next_url)

@app.route('/web/logout')
def web_logout(): session.pop('oauth_web_user_id', None); return redirect(url_for('web_login'))

@app.route('/oauth/authorize', methods=['GET', 'POST'])
def oauth_authorize():
    user = get_current_user_for_oauth_flow() # Pega usuário da SESSÃO FLASK
    if not user: return redirect(url_for('web_login', next=request.url)) # Precisa logar na sessão web primeiro
    if request.method == 'GET': # Mostra formulário de consentimento (que não temos, então auto-aprova)
        try: return authorization.create_authorization_response(grant_user=user)
        except Exception as e: print(f"Erro GET /oauth/authorize: {e}"); return f"Erro: {str(e)}", 400
    # Se POST (simulando envio de formulário de consentimento)
    grant_user = user # Auto-aprova
    return authorization.create_authorization_response(grant_user=grant_user)

@app.route('/oauth/token', methods=['POST'])
def oauth_token(): return authorization.create_token_response()

# --- Rotas API Dispositivos (Protegidas por JWT) ---
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
        return jsonify({'access_token': access_token, 'user_id': user.id, 'username': user.username }), 200 # Retornando user_id e username
    else: return jsonify({'message': 'Senha incorreta.'}), 401

@app.route('/api/add_device', methods=['POST'])
@token_required
def add_device(current_api_user):
    data = request.get_json();
    if not data or 'name' not in data or not data['name'].strip(): return jsonify({'message': 'Nome faltando'}), 400
    try: novo_dispositivo = Device(name=data['name'].strip(), owner=current_api_user); db.session.add(novo_dispositivo); db.session.commit(); return jsonify({'id': novo_dispositivo.id, 'name': novo_dispositivo.name, 'status': novo_dispositivo.status}), 201
    except Exception as e: db.session.rollback(); print(f"Erro add: {e}"); return jsonify({'message': 'Erro servidor add'}), 500

@app.route('/api/devices', methods=['GET'])
@token_required
def get_devices(current_api_user):
    try:
        lista_dispositivos = Device.query.filter_by(user_id=current_api_user.id).all(); dispositivos_formatados = []
        for device in lista_dispositivos: dispositivos_formatados.append({'id': device.id, 'name': device.name, 'status': device.status})
        return jsonify(dispositivos_formatados)
    except Exception as e: print(f"Erro list: {e}"); return jsonify({'message': 'Erro servidor list'}), 500

@app.route('/api/device/<int:device_id>', methods=['GET', 'PUT', 'DELETE'])
@token_required
def specific_device(current_api_user, device_id):
    device = Device.query.filter_by(id=device_id, user_id=current_api_user.id).first_or_404()
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
def control_device(current_api_user, device_id):
    device = Device.query.filter_by(id=device_id, user_id=current_api_user.id).first_or_404()
    data = request.get_json();
    if not data or 'action' not in data: return jsonify({'message': 'Ação faltando'}), 400
    action = str(data['action']).upper();
    if action not in ["ON", "OFF"]: return jsonify({'message': 'Ação inválida'}), 400
    topic = f"devices/{device_id}/command"; payload = action
    print(f"INFO: Backend: POST ID {device_id} (User {current_api_user.id}). MQTT Pub -> T: '{topic}', P: '{payload}'")
    try:
        client_id = f"flask_pub_{os.getpid()}_{device_id}_{time.time()}"; mqttc = paho_mqtt.Client(paho_mqtt.CallbackAPIVersion.VERSION1, client_id=client_id)
        mqttc.connect(MQTT_BROKER_ADDRESS, MQTT_BROKER_PORT, 60); mqttc.loop_start()
        publish_info = mqttc.publish(topic, payload=payload, qos=1); publish_info.wait_for_publish(timeout=5); mqttc.loop_stop(); mqttc.disconnect()
        if publish_info.is_published():
            print(f"INFO: Backend: MQTT pub OK '{topic}'. Aguardando status DB..."); time.sleep(1.0)
            updated_device = Device.query.get(device_id) # Re-query to get current status after MQTT loop
            if updated_device: return jsonify({'id': updated_device.id, 'name': updated_device.name, 'status': updated_device.status}), 200
            else: return jsonify({'message': f'Comando enviado, mas ID {device_id} não encontrado pós-update.'}), 404
        else: print(f"AVISO: Backend: MQTT pub confirm fail '{topic}'."); return jsonify({'message': f'Comando {action} enviado, confirm fail.'}), 202
    except Exception as e: print(f"ERRO: Backend MQTT: {e}"); return jsonify({'message': f'Erro MQTT: {e}'}), 500

# --- Execução do Servidor ---
if __name__ == '__main__':
    if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true': # Evita rodar a thread duas vezes no modo debug com reloader
        print("INFO: Backend: Criando e iniciando thread listener MQTT..."); listener_thread = threading.Thread(target=mqtt_listener_thread_func, daemon=True); listener_thread.start(); print("INFO: Backend: Thread listener MQTT iniciada.")
    print("INFO: Backend: Iniciando servidor Flask..."); app.run(host='0.0.0.0', debug=True, use_reloader=False)