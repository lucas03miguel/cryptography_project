all: run

down:
	docker-compose down
	$(MAKE) run

run:
	docker-compose build
	docker-compose up


