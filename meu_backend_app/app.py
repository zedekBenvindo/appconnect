# Conteúdo INICIAL SIMPLES para: meu_backend_app\app.py
from flask import Flask, jsonify
# from flask_sqlalchemy import SQLAlchemy # SQLAlchemy não é usado nesta versão mínima

app = Flask(__name__)
# db = SQLAlchemy(app) # Não precisamos do DB para este teste mínimo inicial

# Dados de exemplo (dummy data)
dummy_devices_data = [
    {"id": 1, "name": "Luz Teste (Dummy)", "status": "OFF"},
    {"id": 2, "name": "Tomada Sala (Dummy)", "status": "ON"}
]

@app.route('/api/devices', methods=['GET'])
def get_devices_dummy():
    print("INFO: Rota /api/devices chamada, retornando dados dummy.")
    return jsonify(dummy_devices_data)

@app.route('/')
def hello():
    return jsonify(message="Backend Flask Mínimo está no ar!")

if __name__ == '__main__':
    # Comentado db.create_all() pois não temos modelos definidos ainda nesta versão mínima
    # with app.app_context():
    #     db.create_all()
    print("INFO: Iniciando servidor Flask Mínimo...")
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)