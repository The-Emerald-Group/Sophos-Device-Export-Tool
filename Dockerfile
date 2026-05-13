FROM python:3.14.5-slim
WORKDIR /app
RUN pip install --no-cache-dir requests reportlab
COPY app.py .
COPY index.html .
EXPOSE 8080
CMD ["python", "app.py"]
