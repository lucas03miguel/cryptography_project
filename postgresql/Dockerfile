FROM postgres:latest


ENV POSTGRES_USER cripto-database-assignment
ENV POSTGRES_PASSWORD cripto-database-assignment
ENV POSTGRES_DB cripto-database-assignment

COPY cripto-db-schema-pg.sql /docker-entrypoint-initdb.d/

EXPOSE 5432
