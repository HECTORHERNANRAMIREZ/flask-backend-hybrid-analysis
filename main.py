from flask import Flask, request, jsonify
import requests
import time
import os

app = Flask(__name__)

# ✅ Carga la API KEY desde variable de entorno en Railway
API_KEY = os.getenv("API_KEY")

# ✅ Endpoint de prueba
@app.route("/", methods=["GET"])
def home():
    return "🚀 API de Hybrid Analysis activa"

# ✅ Endpoint simplificado para Flutter
@app.route("/analyze_file", methods=["POST"])
def analizar_archivo_para_flutter():
    if 'file' not in request.files:
        return "No se envió ningún archivo", 400

    archivo = request.files['file']
    files = {'file': (archivo.filename, archivo.stream)}
    headers = {
        "User-Agent": "Falcon Sandbox",
        "api-key": API_KEY
    }

    # Subir archivo a Hybrid Analysis
    respuesta = requests.post(
        "https://www.hybrid-analysis.com/api/v2/submit/file",
        headers=headers,
        files=files
    )

    # 🔍 Si falla la subida, mostrar detalles de error
    if respuesta.status_code != 200:
        print("❌ Error al subir archivo a Hybrid Analysis:")
        print("Código:", respuesta.status_code)
        print("Respuesta:", respuesta.text)
        return jsonify({
            "error": "Falló la subida",
            "status_code": respuesta.status_code,
            "respuesta": respuesta.text
        }), 500

    job_id = respuesta.json().get("job_id")

    # Esperar hasta 10 intentos de resultado
    for _ in range(10):
        time.sleep(6)
        r = requests.get(
            f"https://www.hybrid-analysis.com/api/v2/report/summary/{job_id}",
            headers=headers
        )
        if r.status_code == 200:
            data = r.json()
            threat_score = data.get("threat_score", 0)
            verdict = data.get("verdict", "").lower()

            if threat_score >= 70 or "malicious" in verdict:
                return "Archivo sospechoso detectado", 200
            else:
                return "Archivo limpio", 200

    return "Tiempo de espera agotado", 408

# ✅ Ejecutar localmente
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
