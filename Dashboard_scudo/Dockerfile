FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN useradd --create-home --shell /bin/bash scudo

COPY pacchetto_scudo /tmp/pacchetto_scudo
COPY Dashboard_scudo/requirements.txt ./requirements.txt

RUN pip install --upgrade pip && \
    pip install /tmp/pacchetto_scudo && \
    pip install -r requirements.txt && \
    rm -rf /tmp/pacchetto_scudo

COPY Dashboard_scudo /app

RUN chown -R scudo:scudo /app
USER scudo

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=3)" || exit 1

CMD ["streamlit", "run", "dashboard.py", "--server.port=8501", "--server.address=0.0.0.0", "--server.headless=true"]
