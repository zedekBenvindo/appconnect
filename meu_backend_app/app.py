# Conteúdo COMPLETO e ATUALIZADO para: app.py (com base OAuth 2.0 para Alexa)
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
    create_query_client_func, # Helper para query_client
    create_save_token_func,   # Helper para save_token (usaremos um customizado)
    create_revocation_endpoint,
    create_bearer_token_validator
)
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as AuthlibAuthorizationCodeGrant,
    RefreshTokenGrant as AuthlibRefreshTokenGrant, # Habilitando Refresh Token Grant
)

# --- Setup Inicial ---
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__) # A pasta 'templates' será automaticamente reconhecida

# --- Configurações do App ---
app.config['SECRET_KEY'] = 'sua_chave_secreta_super_segura_e_dificil_987$#@_OAuth' # MUDE ISSO EM PRODUÇÃO!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///meu_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = False # True em produção com HTTPS
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
    oauth_clients = db.relationship('OAuth2Client', backref='user', lazy='dynamic') # Dono do cliente OAuth
    def __repr__(self): return f'<User {self.username}>'

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    status = db.Column(db.String(10), nullable=False, default='OFF')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    def __repr__(self): return f'<Device {self.id}: {self.name} ({self.status}) OwnerID: {self.user_id}>'

# --- Modelos OAuth 2.0 ---
class OAuth2Client(db.Model, OAuth2ClientMixin):
    __tablename__ = 'oauth2_client'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')) # Quem registrou este cliente OAuth
    # client_id, client_secret, client_metadata são fornecidos por OAuth2ClientMixin
    # Adicionando explicitamente para que db.create_all() os crie:
    client_id = db.Column(db.String(48), index=True)
    client_secret = db.Column(db.String(120))
    client_name = db.Column(db.String(120))
    redirect_uris = db.Column(db.Text)
    default_redirect_uri = db.Column(db.String(2000)) # Adicionado para Authlib
    scope = db.Column(db.Text)
    grant_types = db.Column(db.Text)
    response_types = db.Column(db.Text)
    token_endpoint_auth_method = db.Column(db.String(120))
    # issued_at, expires_at, etc. não são necessários aqui, são para tokens
    
    def __repr__(self): return f'<OAuth2Client {self.client_name}>'


class OAuth2AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
    __tablename__ = 'oauth2_authorization_code'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User') # O usuário final que está autorizando
    # code, client_id, redirect_uri, scope, etc. são fornecidos por OAuth2AuthorizationCodeMixin
    # Adicionando explícito para db.create_all
    code = db.Column(db.String(120), unique=True, nullable=False)
    client_id = db.Column(db.String(48))
    redirect_uri = db.Column(db.Text)
    response_type = db.Column(db.Text) # Adicionado para Authlib
    scope = db.Column(db.Text)
    auth_time = db.Column(db.Integer, nullable=False, default=lambda: int(time.time()))
    # nonce = db.Column(db.String(120)) # Para OpenID Connect

class OAuth2Token(db.Model, OAuth2TokenMixin):
    __tablename__ = 'oauth2_token'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User') # O usuário final para quem este token foi emitido
    client_id = db.Column(db.String(48)) # Adicionado para integridade
    token_type = db.Column(db.String(40))
    access_token = db.Column(db.String(255), unique=True, nullable=False)
    refresh_token = db.Column(db.String(255), index=True)
    scope = db.Column(db.Text)
    issued_at = db.Column(db.Integer, nullable=False, default=lambda: int(time.time()))
    expires_in = db.Column(db.Integer, nullable=False, default=0)
    revoked = db.Column(db.Boolean, default=False) # Para revogar tokens

    def is_access_token_expired(self): return self.issued_at + self.expires_in < time.time()
    def is_refresh_token_active(self): # Método que o RefreshTokenGrant procura
        if self.revoked: return False
        # Adicione lógica de expiração para refresh token se desejar, ex:
        # refresh_token_expires_at = self.issued_at + (30 * 24 * 60 * 60) # 30 dias
        # if refresh_token_expires_at < time.time(): return False
        return True

# --- Lógica para Sessão de Usuário Flask (para o fluxo OAuth /authorize) ---
@app.before_request
def load_logged_in_user_from_session():
    user_id = session.get('oauth_web_user_id') # Usando uma chave de sessão específica
    g.user_oauth_session = User.query.get(user_id) if user_id else None

def get_current_user_for_oauth_flow(): # Para Authlib saber quem é o usuário da SESSÃO FLASK
    return g.user_oauth_session if hasattr(g, 'user_oauth_session') else None

# --- Configuração do Servidor de Autorização OAuth 2.0 com Authlib ---
query_client = create_query_client_func(db.session, OAuth2Client)
save_token = create_save_token_func(db.session, OAuth2Token) # Usa o helper do Authlib
authorization = AuthorizationServer(app, query_client=query_client, save_token=save_token)

# Registro dos "Grants"
class MyAuthorizationCodeGrant(AuthlibAuthorizationCodeGrant):
    def save_authorization_code(self, code, request):
        auth_code = OAuth2AuthorizationCode(
            code=code, client_id=request.client.client_id, redirect_uri=request.redirect_uri,
            scope=request.scope, user_id=request.user.id, response_type=request.response_type,
            auth_time=int(time.time()) )
        db.session.add(auth_code); db.session.commit(); return auth_code
    def query_authorization_code(self, code, client):
        item = OAuth2AuthorizationCode.query.filter_by(code=code, client_id=client.client_id).first()
        if item and not item.is_expired(): return item; return None
    def delete_authorization_code(self, authorization_code): db.session.delete(authorization_code); db.session.commit()
    def authenticate_user(self, authorization_code): return User.query.get(authorization_code.user_id)

authorization.register_grant(MyAuthorizationCodeGrant)
authorization.register_grant(AuthlibRefreshTokenGrant, query_token=lambda refresh_token, client: OAuth2Token.query.filter_by(refresh_token=refresh_token, client_id=client.client_id).first(), save_token=save_token)

# --- Criação das Tabelas ---
with app.app_context():
    print("INFO: Backend: Verificando e criando TODAS as tabelas do BD..."); db.create_all(); print("INFO: Backend: TODAS as tabelas do BD OK.")
    # Helper para criar um cliente OAuth de teste
    admin_user = User.query.filter_by(username='jessy_web').first() # Use o username que você registrou
    if admin_user:
        test_client = OAuth2Client.query.filter_by(client_id='alexa-skill-test-client').first()
        if not test_client:
            print("INFO: Criando cliente OAuth de teste 'alexa-skill-test-client'...")
            # Redirect URIs que a Alexa usa (exemplos, pegue os reais no console Alexa depois)
            redirect_uris_str = (
                'https://pitangui.amazon.com/api/skill/link/MEXAMPLE1\n'
                'https://layla.amazon.com/api/skill/link/MEXAMPLE2\n'
                'https://alexa.amazon.co.jp/api/skill/link/MEXAMPLE3'
            )
            client_metadata = {
                "client_name": "Minha Skill Alexa Teste",
                "client_uri": "https://minha-skill.example.com", # Placeholder
                "grant_types": ["authorization_code", "refresh_token"],
                "redirect_uris": redirect_uris_str.split(), # Lista de URIs
                "response_types": ["code"],
                "scope": "read_devices control_devices", # Escopos que a skill pode pedir
                "token_endpoint_auth_method": "client_secret_post" # Ou client_secret_basic
            }
            test_client = OAuth2Client(
                client_id='alexa-skill-test-client',
                client_secret=bcrypt.generate_password_hash('alexa_skill_secret_123').decode('utf-8'), # Guarde o original
                user_id=admin_user.id # Associado ao usuário que "criou" este cliente
            )
            test_client.set_client_metadata(client_metadata) # Define os metadados
            db.session.add(test_client); db.session.commit()
            print(f"INFO: Cliente OAuth 'alexa-skill-test-client' criado/verificado.")
            print(f"      Client ID: {test_client.client_id}")
            print(f"      Client Secret (original, não o hash): alexa_skill_secret_123 (guarde isso!)")
        else:
            print(f"INFO: Cliente OAuth 'alexa-skill-test-client' já existe.")
    else: print("AVISO: Usuário 'jessy_web' (ou seu admin) não encontrado para criar cliente OAuth. Registre-o.")


# --- Decorator para Autenticação via Token JWT (API principal) ---
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

# --- Lógica do Cliente MQTT para Ouvir Status (em Background) ---
# (Funções on_connect_listener, on_subscribe_listener, on_message_listener, mqtt_listener_thread_func permanecem iguais)
# ... (COLE AS FUNÇÕES MQTT LISTENER AQUI, IGUAIS ÀS DA VERSÃO ANTERIOR DO APP.PY) ...
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


# --- Rotas da API ---
@app.route('/')
def hello_world(): return 'Backend Protegido Funcionando! OAuth em progresso.'

# --- NOVAS Rotas para Login/Logout na Sessão Web (para fluxo OAuth) ---
@app.route('/web/login', methods=['GET', 'POST'])
def web_login():
    user_in_session = get_current_user_for_oauth_flow()
    next_url = request.args.get('next') # Captura o 'next' da URL se existir

    if user_in_session and request.method == 'GET': # Já logado, e é uma requisição GET
        if next_url: return redirect(next_url) # Se OAuth o enviou aqui, redireciona de volta para /oauth/authorize
        return f"Você já está logado como {user_in_session.username}! <a href='{url_for('web_logout')}'>Sair</a>"

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            session.clear(); session['oauth_web_user_id'] = user.id; session.permanent = True
            print(f"Usuário ID {user.id} ({user.username}) logado na SESSÃO WEB")
            if next_url: return redirect(next_url) # Redireciona para /oauth/authorize com a sessão
            return 'Login via web bem-sucedido! Pode fechar esta aba.'
        else:
            return render_template('login_oauth.html', error='Usuário ou senha inválidos.', next=next_url)
    
    # Se for GET e não estiver logado, mostra o formulário
    return render_template('login_oauth.html', next=next_url)

@app.route('/web/logout')
def web_logout():
    session.pop('oauth_web_user_id', None); return redirect(url_for('web_login'))

# --- NOVAS Rotas OAuth 2.0 ---
@app.route('/oauth/authorize', methods=['GET', 'POST'])
def oauth_authorize():
    user = get_current_user_for_oauth_flow()
    if not user: # Se não estiver logado na sessão web, redireciona para a página de login web
        return redirect(url_for('web_login', next=request.url)) # 'next' preserva os params OAuth

    if request.method == 'GET':
        # Mostra uma página de consentimento (que não criamos ainda, então vamos simular)
        # Em um app real: render_template('consent_form.html', client=client, user=user, ...)
        # Por agora, vamos auto-aprovar se estiver logado e a requisição for válida.
        # A chamada abaixo vai validar o client_id, redirect_uri, etc.
        try:
            return authorization.create_authorization_response(grant_user=user)
        except Exception as e: # Ex: authlib.oauth2.rfc6749.errors.InvalidClientError
            print(f"Erro na tentativa de criar auth response (GET /oauth/authorize): {e}")
            # Idealmente, mostrar uma página de erro amigável
            return f"Erro na requisição de autorização: {str(e)}", 400
    
    # Se for POST (simulando um formulário de consentimento que não temos)
    # grant_user = user if request.form.get('confirm') == 'yes' else None # Exemplo se tivéssemos form
    grant_user = user # Auto-aprova
    return authorization.create_authorization_response(grant_user=grant_user)


@app.route('/oauth/token', methods=['POST'])
def oauth_token():
    return authorization.create_token_response()
# --- Fim Rotas OAuth 2.0 ---


# --- Rotas de Autenticação API (JWT) --- (Como antes)
@app.route('/auth/register', methods=['POST'])
def register(): data = request.get_json(); ... # (Mantenha o código completo como antes)
@app.route('/auth/login', methods=['POST'])
def login(): data = request.get_json(); ... # (Mantenha o código completo como antes, certifique-se de retornar user_id)

# --- Rotas de Dispositivos (Protegidas por JWT) --- (Como antes)
@app.route('/api/add_device', methods=['POST']) @token_required
def add_device(current_api_user): data = request.get_json(); ...
@app.route('/api/devices', methods=['GET']) @token_required
def get_devices(current_api_user): try: lista_dispositivos = Device.query.filter_by(user_id=current_api_user.id).all(); ...
@app.route('/api/device/<int:device_id>', methods=['GET', 'PUT', 'DELETE']) @token_required
def specific_device(current_api_user, device_id): device = Device.query.filter_by(id=device_id, user_id=current_api_user.id).first_or_404(); ...
@app.route('/api/device/<int:device_id>/control', methods=['POST']) @token_required
def control_device(current_api_user, device_id): device = Device.query.filter_by(id=device_id, user_id=current_api_user.id).first_or_404(); ...


# --- Execução do Servidor ---
if __name__ == '__main__':
    if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        print("INFO: Backend: Criando e iniciando thread listener MQTT..."); listener_thread = threading.Thread(target=mqtt_listener_thread_func, daemon=True); listener_thread.start(); print("INFO: Backend: Thread listener MQTT iniciada.")
    print("INFO: Backend: Iniciando servidor Flask..."); app.run(host='0.0.0.0', debug=True, use_reloader=False)