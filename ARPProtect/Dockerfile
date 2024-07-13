FROM python:3.9-slim

WORKDIR /usr/src/app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 80 5000

CMD ["sh", "-c", "python3 arpshield.py & python3 app.py"]
