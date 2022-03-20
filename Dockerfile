# Create a ubuntu base image with python 3 installed
FROM python:3.8

# Set the working directory
WORKDIR /app

# Copy requirements.txt
COPY requirements.txt .

# Install dependencies
RUN pip install -r requirements.txt

# Copy project files
COPY . .

# Run the application
CMD ["python", "app.py"]