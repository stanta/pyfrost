# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy the current directory contents into the container at /usr/src/app
COPY . .

# Install any needed packages specified in setup.py
RUN apt-get update && apt-get install -y build-essential libgmp-dev
RUN pip install .

# The command to run the app will be specified in docker-compose.yml
# The ports will be exposed in docker-compose.yml
