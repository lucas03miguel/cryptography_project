PORT ?= 8080

run:
	@echo "Starting Flask server on port $(PORT)..."
	@if lsof -i :$(PORT) > /dev/null 2>&1; then \
	    echo "Port $(PORT) is already in use. Checking the process..."; \
	    sudo lsof -i :$(PORT); \
	    echo "Killing the process on port $(PORT)..."; \
	    sudo kill -9 $$(sudo lsof -t -i :$(PORT)); \
	else \
	    echo "Port $(PORT) is available. Starting server..."; \
	fi
	# docker stop web
	@python3 website/app.py

run-alt:
	@read -p "Enter the port you want to use: " PORT; \
	if lsof -i :$$PORT > /dev/null 2>&1; then \
	    echo "Port $$PORT is already in use. Checking the process..."; \
	    sudo lsof -i :$$PORT; \
	    echo "Killing the process on port $$PORT..."; \
	    sudo kill -9 $$(sudo lsof -t -i :$$PORT); \
	else \
	    echo "Port $$PORT is available. Starting server..."; \
	fi
	# docker stop web
	@python3 website/app.py --port=$$PORT

.PHONY: run run-alt
