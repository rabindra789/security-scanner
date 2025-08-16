# Use official Python base image
FROM python:3.12-slim

RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates templates

EXPOSE 1818

CMD ["python", "app.py"]