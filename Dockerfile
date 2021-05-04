FROM python:3.6-slim
RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app
ADD requirements.txt .
ENV https_proxy=""
ENV http_proxy="
ENV no_proxy="127.0.0.1,localhost"
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install http://repo/socutils-1.5.8-py3-none-any.whl --no-cache-dir
ENV https_proxy=""
ENV http_proxy=""
ADD . /usr/src/app
ENTRYPOINT ["python3"]
CMD ["main.py"]

##for local build
#FROM python:3.6-slim
#RUN mkdir -p /usr/src/app
#ADD . /usr/src/app
#WORKDIR /usr/src/app
#RUN pip install --upgrade pip \
#    && pip install --no-cache-dir -r requirements.txt \
#    && pip install http://repo/socutils-1.5.8-py3-none-any.whl
#ENTRYPOINT ["python3"]
#CMD ["main.py"]