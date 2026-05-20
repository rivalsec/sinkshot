FROM mcr.microsoft.com/playwright/python:v1.58.0-jammy

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY mthook.py config.yaml ./
COPY js/ ./js/

ENTRYPOINT ["python", "mthook.py"]
