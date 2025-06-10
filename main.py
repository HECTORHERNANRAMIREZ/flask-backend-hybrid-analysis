from flask import Flask, request, jsonify
import requests
import time
import os

app = Flask(__name__)

# ✅ Carga de la API Key desde las variables de entorno en Railway
API_KEY = os.getenv("API_KEY")

# ✅ Ruta raíz para comprobar si la API está activa
@app.route("/", methods=["GET"])
def home():
    return "🚀 API de Hybrid Analysis activa"

# ✅ Ruta JSON para escanear un archivo (original, conserva esta si la usas en pruebas web)
@app.route("/escanear", methods=["POST"])
def escanear_archivo():
    if 'file' not in request.files:
        return jsonify({"error": "Archivo no encontrado"}), 400

    archivo = request.files['file']
    files = {'file': (archivo.filename, archivo.stream)}
    headers = {
        "User-Agent": "Falcon Sandbox",
        "api-key": API_KEY
    }

    # Paso 1: Subir archivo
    respuesta = requests.post(
        "https://www.hybrid-analysis.com/api/v2/submit/file",
        headers=headers,
        files=files
    )

    if respuesta.status_code != 200:
        return jsonify({"error": "No se pudo subir el archivo"}), 500

    job_id = respuesta.json().get("job_id")

    # Paso 2: Esperar el resultado hasta 60 segundos (~10 intentos)
    for _ in range(10):
        time.sleep(6)
        r = requests.get(
            f"https://www.hybrid-analysis.com/api/v2/report/summary/{job_id}",
            headers=headers
        )
        if r.status_code == 200:
            data = r.json()
            return jsonify({
                "threat_score": data.get("threat_score"),
                "verdict": data.get("verdict"),
                "tags": data.get("classification_tags", []),
                "job_id": job_id
            })

    return jsonify({"error": "No se obtuvo resultado a tiempo"}), 408

# ✅ Nuevo endpoint compatible con Flutter (texto plano)
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

    if respuesta.status_code != 200:
        return "Error al subir archivo", 500

    job_id = respuesta.json().get("job_id")

    # Esperar resultado hasta 60 segundos (~10 intentos)
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

# ✅ Configuración para producción en Railway
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
