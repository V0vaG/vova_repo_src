FROM python:3.9-slim

WORKDIR ~/

COPY ./requirements.txt .

RUN pip install -r requirements.txt

COPY . .


# Make sure the script is executable and run it
RUN chmod +x repo_make.sh && ./repo_make.sh

# Run the app
CMD ["python3", "-m", "http.server", "5000"]
