# FROM python:3.11-slim AS build
# ENV PYTHONDONTWRITEBYTECODE=1
# ENV PYTHONUNBUFFERED=1

# WORKDIR /app
# COPY requirements.txt .
# RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# FROM python:3.11-slim
# WORKDIR /app
# RUN useradd --create-home appuser
# COPY --from=build /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
# COPY . /app
# RUN chown -R appuser:appuser /app
# USER appuser

# EXPOSE 8000
# ENV PORT 8000


# CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "app:app"]
