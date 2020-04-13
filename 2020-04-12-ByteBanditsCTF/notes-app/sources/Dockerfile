FROM python:alpine

RUN apk add --no-cache postgresql-libs && \
		apk add --no-cache --virtual .build-deps gcc musl-dev postgresql-dev chromium udev ttf-freefont

COPY . /app

WORKDIR /app

RUN pip install -r requirements.txt

RUN pip install pyppeteer

# Create a group and user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Tell docker that all future commands should run as the appuser user
USER appuser
