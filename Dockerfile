# Use a lightweight official Python image
FROM python:3.11-slim

# Install system utilities needed for compiling packages and packet sniffing
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Set working directory inside the container
WORKDIR /app

# Copy dependency definition
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy all project code
COPY . .

# Expose port 5000 for the web dashboard and APIs
EXPOSE 5000

# Prevent Python from buffering stdout/stderr (crucial for container logs)
ENV PYTHONUNBUFFERED=1

# Start monitor.py by default (real monitor mode)
CMD ["python", "backend/monitor.py"]
