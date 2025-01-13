# Usa a imagem base do Python
FROM python:3.12-alpine3.18

# Atualiza pacotes e instala dependências necessárias para o sistema
RUN apk update && apk add --no-cache \
    postgresql-dev \
    gcc \
    python3-dev \
    musl-dev

# Define o diretório de trabalho
WORKDIR /app

# Copia todo o código para o contêiner
COPY . /app

# Instala todas as dependências diretamente no Dockerfile
RUN pip install --no-cache-dir \
    Flask==3.0.0 \
    Flask-WTF \
    Flask-Session \
    psycopg2-binary \
    pyotp \
    qrcode[pil]

# Cria o diretório de logs
RUN mkdir -p logs

# Expõe a porta usada pelo Flask
EXPOSE 5000

# Comando para iniciar a aplicação
CMD ["python", "app.py"]
