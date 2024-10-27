#!/bin/bash

# Source the .env file
set -a
source .env.prod
set +a

# Build and push Docker image
docker build -t gcr.io/$PROJECT_ID/discord-bot:latest ./bot
docker push gcr.io/$PROJECT_ID/discord-bot:latest

# Export environment variables
export TF_VAR_project_id=$PROJECT_ID
export TF_VAR_upstash_email=$UPSTASH_EMAIL
export TF_VAR_upstash_api_key=$UPSTASH_API_KEY
export TF_VAR_discord_token=$DISCORD_TOKEN
export TF_VAR_resend_api_key=$RESEND_API_KEY
export TF_VAR_docker_image=gcr.io/$PROJECT_ID/discord-bot:latest

# Initialize and apply Terraform
cd infra
terraform init
# terraform apply -auto-approve
terraform apply