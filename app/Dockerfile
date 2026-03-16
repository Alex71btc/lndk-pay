FROM alex71btc/lndk:v0.3.0 AS lndkbin

FROM python:3.12-slim

WORKDIR /app

COPY --from=lndkbin /usr/local/bin/lndk-cli /usr/local/bin/lndk-cli

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend ./backend
COPY frontend ./frontend
COPY assets /app/assets

EXPOSE 8081

CMD ["uvicorn", "backend.app:app", "--host", "0.0.0.0", "--port", "8081"]
