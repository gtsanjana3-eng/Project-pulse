FROM mcr.microsoft.com/playwright/python:v1.56.0-noble
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PP_ENV=production PP_BROWSER_NO_SANDBOX=1
CMD ["uvicorn", "projectpulse.api:app_factory", "--factory", "--host", "0.0.0.0", "--port", "8000"]
