FROM python:3.12-slim

WORKDIR /app
RUN pip install --no-cache-dir flask redis

COPY app.py .

EXPOSE 8080
CMD ["python", "app.py"]
