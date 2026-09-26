FROM mcr.microsoft.com/playwright/python:v1.55.0-noble
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN playwright install --with-deps firefox chromium webkit
COPY worker.py .
EXPOSE 8090
CMD ["python", "worker.py"]
