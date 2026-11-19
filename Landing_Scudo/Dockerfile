FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN useradd --create-home --shell /bin/bash scudo

COPY pacchetto_scudo /tmp/pacchetto_scudo
COPY Landing_Scudo/requirements.txt ./requirements.txt

RUN pip install --upgrade pip && \
    pip install /tmp/pacchetto_scudo && \
    pip install -r requirements.txt && \
    rm -rf /tmp/pacchetto_scudo

COPY Landing_Scudo /app

RUN chown -R scudo:scudo /app
USER scudo

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3)" || exit 1

CMD ["uvicorn", "Landing_Page:app", "--host", "0.0.0.0", "--port", "8080"]
