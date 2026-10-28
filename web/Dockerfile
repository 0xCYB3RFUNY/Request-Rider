FROM python:3.13-slim@sha256:8296499feed1c18bd8064c279d45e2a1b4b6be586f8b9e16dcf2aaf843480d88
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["sh", "-c", "python manage.py migrate --noinput && python manage.py runserver 0.0.0.0:8000"]
