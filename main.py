from flask import Flask, request, jsonify
import requests
import time

app = Flask(__name__)

# ✅ Clave API de VirusTotal
VT_API_KEY = "3ea4bd8bfc3532211cde4598a2d2aaf515c86bfc975703c73817a9ca596f59ca"
headers = {
    "x-apikey": VT_API_KEY
}

# ✅ Prueba de vida
@app.route("/", methods=["GET"])
def home():
    return "🚀 API con VirusTotal activa"

# ✅ Análisis de archivo
@app.route("/analyze_file", methods=["POST"])
def analizar_archivo():
    if 'file' not in request.files:
        return "No se envió ningún archivo", 400

    archivo = request.files['file']
    files = {
        "file": (archivo.filename, archivo.stream)
    }

    # Enviar archivo a VirusTotal
    print(f"📤 Enviando archivo a VirusTotal: {archivo.filename}")
    respuesta = requests.post(
        "https://www.virustotal.com/api/v3/files",
        headers=headers,
        files=files
    )

    if respuesta.status_code != 200:
        print("❌ Error al subir archivo:")
        print("Código:", respuesta.status_code)
        print("Respuesta:", respuesta.text)
        return jsonify({
            "error": "Fallo en subida",
            "status_code": respuesta.status_code,
            "respuesta": respuesta.text
        }), 500

    # Obtener ID del análisis
    analysis_id = respuesta.json()["data"]["id"]
    print(f"📥 ID del análisis recibido: {analysis_id}")

    # Consultar resultado repetidamente
    for intento in range(20):  # Hasta 100 segundos (20 x 5)
        print(f"⌛ Intento {intento + 1}/20 esperando análisis...")
        time.sleep(5)

        resultado = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        )

        if resultado.status_code != 200:
            print("❌ Error al obtener el análisis:", resultado.text)
            continue

        data = resultado.json()
        status = data["data"]["attributes"]["status"]

        if status == "completed":
            stats = data["data"]["attributes"]["stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            print(f"🧪 Resultado → Malicious: {malicious}, Suspicious: {suspicious}")

            if malicious > 0 or suspicious > 0:
                return "Archivo sospechoso detectado", 200
            else:
                return "Archivo limpio", 200

    print("⏱️ Tiempo de espera agotado para ID:", analysis_id)
    return "Tiempo de espera agotado", 408

# ✅ Local (solo si ejecutas localmente)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
