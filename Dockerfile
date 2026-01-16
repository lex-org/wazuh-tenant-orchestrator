FROM python:3.11-slim

WORKDIR /app

# Install Poetry
RUN pip install --no-cache-dir poetry

# Copy dependency files first (for better layer caching)
COPY pyproject.toml poetry.lock ./

# Install dependencies (no dev dependencies, no virtualenv in container)
RUN poetry config virtualenvs.create false && \
    poetry install --only main --no-interaction --no-ansi

COPY . .

ENTRYPOINT ["python", "main.py"]
