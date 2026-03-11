# Use Python 3.11.9 — fixes 'type' subscriptable error with transformers + numpy
FROM python:3.11.9

# Set environment variables 
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Copy and install Python dependencies
COPY requirements.txt .

# Install PyTorch CPU-only first to avoid downloading massive CUDA packages (saves ~2GB)
RUN pip install --upgrade pip && \
    pip install --no-cache-dir torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir numpy==1.26.4

# Copy the entire backend application
COPY . .

# Create the security_logs directory (fallback if volume not mounted)
RUN mkdir -p security_logs

# Expose the API port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]