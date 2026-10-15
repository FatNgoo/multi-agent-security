FROM python:3.12-slim
WORKDIR /app
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
COPY requirements.txt ./
RUN uv pip install --system -r requirements.txt
COPY app ./app
COPY data/fixtures ./data/fixtures
ENV PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["uvicorn", "app.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
