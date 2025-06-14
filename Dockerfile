FROM python:3.13-slim
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 7000
HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:7000/ || exit 1
CMD ["python", "app_copy1.py"]