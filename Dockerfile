# Use an official Python 3.11 slim image
FROM python:3.11.9-slim

# Set environment variables to prevent Python from writing .pyc files
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt /app/

# Install the dependencies
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy the rest of your application code into the container
COPY . /app/

# The command to run your application using shell form to ensure $PORT substitution
CMD gunicorn --bind 0.0.0.0:$PORT app:app

