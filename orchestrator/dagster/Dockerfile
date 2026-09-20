FROM python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 DAGSTER_HOME=/opt/dagster/home
WORKDIR /opt/app
RUN apt-get update && apt-get install -y --no-install-recommends git=1:2.47.3-0+deb13u1 ssdeep=2.14.1+git20180629.57fcfff-3+b2 libfuzzy2=2.14.1+git20180629.57fcfff-3+b2 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt requirements.lock.txt ./
RUN pip install --no-cache-dir -r requirements.txt -c requirements.lock.txt && pip check
COPY dagster.yaml workspace.yaml /opt/dagster/home/
# The runtime may be started as the operator's uid (compose `user:`), which has no passwd entry and
# owns nothing in the image. A named volume takes its mode from this directory when first created.
RUN mkdir -p /var/dagster && chmod 1777 /var/dagster /opt/dagster/home
COPY definitions.py /opt/app/
