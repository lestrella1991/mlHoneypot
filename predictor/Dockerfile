FROM python:3.10-slim

WORKDIR /app

# crea los puntos de montaje dentro de la imagen
RUN mkdir -p /app/logs /data

COPY predict/model/ /app/model/
COPY ./predict/zeek_tail_predict.py /app/
COPY ./predict/zeek_predict_bridge.py /app/

RUN pip install --no-cache-dir joblib pandas numpy scikit-learn

# si corrés como usuario no-root, asegurá permisos:
# RUN chown -R 1000:1000 /app
# USER 1000

RUN pip install --no-cache-dir joblib pandas numpy scikit-learn

# Montá /logs del host a /app/logs dentro del contenedor
VOLUME ["/app/logs","/data"]

# Comando que mantiene la inferencia viva
CMD ["python", "zeek_tail_predict.py", "--model", "/app/model/gridsearch_v3.joblib", "--conn_json", "/app/logs/conn.log","--malicious-threshold", "0.75","--suspicious-threshold","0.65","--out_ips","/data/detected_ips.txt"]