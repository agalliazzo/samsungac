FROM python:3.10-alpine
ADD main.py /
ADD samsung_discovery.py /
ADD requirements.txt /
ADD config.json /

RUN pip install -r requirements.txt

CMD ["python", "./main.py"]