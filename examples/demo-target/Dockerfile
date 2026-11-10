FROM python:3.12-slim-bookworm
RUN pip install --no-cache-dir "flask>=3,<4" "cryptography>=43" "paramiko>=3.4"
WORKDIR /app
COPY app.py .
EXPOSE 8443 8080 3306 2222
CMD ["python", "app.py"]
