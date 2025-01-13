# Utilizar uma imagem base do Python
FROM python:3.9

# Instalar dependências necessárias
RUN apt-get update && apt-get install -y nginx

# Instalar pacotes Python
RUN pip install flask flask-socketio cryptography

# Copiar o código da aplicação
COPY ./website /app

# Copiar a configuração do NGINX
COPY ./nginx/nginx.conf /etc/nginx/nginx.conf

# Copiar os certificados
COPY ./myCA /etc/ssl/certs

# Tornar o NGINX e o Flask executáveis
RUN chmod +x /etc/nginx/nginx.conf

# Expor as portas necessárias
EXPOSE 80 443

# Comando para testar e iniciar o NGINX e o Flask
CMD ["sh", "-c", "nginx -t && service nginx start && python /app/app.py"]
