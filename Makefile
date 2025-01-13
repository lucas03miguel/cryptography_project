all: run then

run:
	docker-compose build

then:
	docker-compose up

