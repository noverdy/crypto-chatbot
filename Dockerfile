FROM python:3.11-slim-buster


WORKDIR /app

COPY ./src .
COPY .env .
RUN pip3 install --no-cache-dir -r requirements.txt

EXPOSE 5000
USER nobody
CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0"]
