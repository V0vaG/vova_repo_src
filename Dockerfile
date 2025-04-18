FROM python:3.9-slim

COPY . .

RUN bash repo_make.sh

CMD python3 -m http.server 9090
