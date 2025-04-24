FROM python:3.13-slim
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 5001
HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:5001/ || exit 1
CMD ["python", "app_copy1.py"]