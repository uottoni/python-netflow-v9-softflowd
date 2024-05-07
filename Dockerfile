FROM python:3.9-slim
# Or any preferred Python version.
#ADD main.py .
RUN pip install clickhouse-connect

ENV CLICKHOUSE_SERVER="172.20.99.121"
ENV CLICKHOUSE_USER="default"
ENV CLICKHOUSE_PASS="Rz2010sql"
ENV LISTEN_ADDRESS="0.0.0.0"
ENV LISTEN_PORT="2055"
EXPOSE $LISTEN_PORT/udp
WORKDIR "/app"
COPY "./collector.py" "/app/collector.py"
COPY "./netflow/" "/app/netflow"
#CMD [“python”, “/app/collector.py”] 
ENTRYPOINT ["python3", "/app/collector.py"]
# Or enter the name of your unique directory and parameter set.