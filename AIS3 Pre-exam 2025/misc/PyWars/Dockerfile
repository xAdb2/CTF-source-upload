FROM python:3.9-slim

WORKDIR /app

RUN useradd -m appuser

COPY ./src/requirements.txt . 
RUN pip install --no-cache-dir -r requirements.txt

COPY ./src /app

RUN mkdir -p /app/uploads /app/flags

RUN echo "AIS3{Fake_Flag_TomorinIsCute}" > /app/flags/flag_$(cat /proc/sys/kernel/random/uuid).txt

RUN chmod -R 755 /app

RUN chmod -R 733 /app/uploads
RUN chmod 755 /app/flags

EXPOSE 10000

USER appuser

CMD ["python3", "server.py"]
