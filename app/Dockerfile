FROM python:3.9-slim

WORKDIR ~/

COPY ./requirements.txt .

RUN pip install -r requirements.txt

COPY . .

RUN bash repo_make.sh

CMD python3 -m http.server 5000
