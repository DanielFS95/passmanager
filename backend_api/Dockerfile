FROM python:3.13-slim

RUN apt-get update && \
    apt-get install -y \
    pkg-config \
    gcc \
    mariadb-client \
    libmariadb-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN python -m pip install -r requirements.txt

EXPOSE 8000

ENTRYPOINT ["python", "-m" , "main_api"]
