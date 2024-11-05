# Use the official Python image as the base image
FROM python:3.10-slim-bookworm AS base

# Copy uv binaries
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

# Copy dependency files for installation
COPY pyproject.toml uv.lock ./

# Install dependencies
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install --system -r pyproject.toml

# Copy the main application file
COPY bot.py ./

# Compile bytecode (this step might be redundant if UV_COMPILE_BYTECODE is set)
RUN python -m compileall .

# Expose the port the app runs on
EXPOSE 8080

# Set the command to run the application
CMD ["python", "bot.py"]