FROM python:3.12-slim
WORKDIR /frontend
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
COPY frontend/requirements.txt /frontend/requirements.txt
RUN uv pip install --system -r /frontend/requirements.txt
COPY frontend/app.py /frontend/app.py
ENV PYTHONUNBUFFERED=1
EXPOSE 8501
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501", "--server.headless=true"]
