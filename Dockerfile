FROM python:3.9-slim

COPY . .

CMD python3 -m http.server 9090
