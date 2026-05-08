FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ntopng_mcp.py .

EXPOSE 3002

CMD ["python", "ntopng_mcp.py"]
