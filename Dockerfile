FROM python:3.9-slim

WORKDIR /app

# Install iputils-ping for the ping command
RUN apt-get update && apt-get install -y iputils-ping && rm -rf /var/lib/apt/lists/*

# Copy the server script and files
COPY server.py .
COPY secret.txt .
COPY public ./public

# Expose the port
EXPOSE 8000

# Run the server
CMD ["python", "server.py"]
