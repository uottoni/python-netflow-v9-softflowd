FROM python:3.9 
# Or any preferred Python version.
ADD main.py .
RUN pip install clickhouse-connect
WORKDIR /app
COPY ["\\netflow\", "\\netflow"]
CMD [“python”, “./collector.py”] 
# Or enter the name of your unique directory and parameter set.