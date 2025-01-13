# Utilizar uma imagem base do Python
FROM python:3.12

# Atualizar pacotes e instalar dependências do sistema
RUN apt-get update && apt-get install -y \
    libpq-dev \
    gcc \
    python3-dev \
    musl-dev \
    nginx

# Define o diretório de trabalho
WORKDIR /app

# Copiar o ficheiro requirements.txt primeiro (para usar o cache)
COPY ./website/requirements.txt /app/requirements.txt

# Instalar dependências Python
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copiar o código da aplicação
COPY ./website /app

# Copiar a configuração do NGINX
COPY ./nginx/nginx.conf /etc/nginx/nginx.conf

# Copiar os certificados SSL
COPY ./myCA /etc/ssl/certs

# Criar o diretório de logs
RUN mkdir -p logs

# Expor as portas necessárias
EXPOSE 80 443 5000

# Comando para iniciar o NGINX e o Flask
CMD ["sh", "-c", "nginx -t && service nginx start && python /app/app.py --reload"]

