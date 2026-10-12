
FROM python:3.12-slim

# Install uv from official Astral image
COPY --from=ghcr.io/astral-sh/uv:0.12.19 \
    /uv /uvx /bin/

WORKDIR /app

# Python and uv configuration
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install dependencies
COPY requirements.txt .

RUN uv pip install --system -r requirements.txt

# Copy application source
COPY app/ ./app/

# Non-root runtime user
RUN useradd --create-home appuser
USER appuser

EXPOSE 8000

# Start FastAPI
CMD ["uvicorn", "app.api.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000"]
