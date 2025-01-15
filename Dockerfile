FROM python:3.12

RUN apt-get update && apt-get install -y \
    libpq-dev \
    gcc \
    python3-dev \
    musl-dev \
    nginx

WORKDIR /app

COPY ./requirements.txt /requirements.txt

RUN pip install --no-cache-dir -r /requirements.txt

COPY ./website /app

COPY ./nginx/nginx.conf /etc/nginx/nginx.conf

COPY ./certificates /etc/ssl/certs

COPY ./postgresql/cripto-db-schema-pg.sql /docker-entrypoint-initdb.d/cripto-db-schema-pg.sql

RUN mkdir -p logs

EXPOSE 80 443 5000

CMD ["sh", "-c", "nginx -t && service nginx start && python /app/app.py --reload"]
