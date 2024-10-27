variable "project_id" {
  description = "Google Cloud project ID"
  type        = string
}

variable "region" {
  description = "Google Cloud region"
  type        = string
  default     = "asia-south1"
}

variable "upstash_email" {
  description = "Upstash account email"
  type        = string
}

variable "upstash_api_key" {
  description = "Upstash API key"
  type        = string
}

variable "upstash_region" {
  description = "Upstash Redis database region"
  type        = string
  default     = "ap-south-1"
}

variable "docker_image" {
  description = "Docker image for the Discord bot"
  type        = string
}

variable "discord_token" {
  description = "Discord bot token"
  type        = string
}

variable "resend_api_key" {
  description = "Resend API key"
  type        = string
}

