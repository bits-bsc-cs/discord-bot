# Use the official Python image as the base image
FROM python:3.10-slim-bookworm AS base

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV UV_SYSTEM_PYTHON=1
ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy
ENV PORT=8080

# Set the working directory
WORKDIR /app

# Copy only the necessary files for dependency installation
COPY pyproject.toml uv.lock ./

# Install dependencies
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install --system -r pyproject.toml

# Copy the rest of the application code
COPY bot.py ./

# Compile bytecode
RUN python -m compileall .

# Expose the port the app runs on
EXPOSE 8080

# Set the command to run the application
CMD ["python", "bot.py"]