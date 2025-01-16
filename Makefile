all: run

down:
	docker-compose down
	rm -rf ./certificates/clients/* ./certificates/Message_Userkeys/* # Apaga os ficheiros das pastas
	$(MAKE) run

run:
	docker-compose build
	docker-compose up