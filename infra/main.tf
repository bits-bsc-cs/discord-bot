terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "6.8.0"
    }
    upstash = {
      source  = "upstash/upstash"
      version = "1.5.3"
    }
    time = {
      source  = "hashicorp/time"
      version = "0.12.1"
    }
  }
  required_version = "~> 1.9"
}

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "upstash" {
  email   = var.upstash_email
  api_key = var.upstash_api_key
}

resource "upstash_redis_database" "redis-db" {
  database_name  = "bits-bot-redis"
  region         = "global"
  primary_region = var.upstash_region
  tls            = "true"
}

resource "google_project_service" "run_api" {
  service            = "run.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "container_registry_api" {
  service            = "containerregistry.googleapis.com"
  disable_on_destroy = false
}

resource "time_sleep" "wait_30_seconds" {
  depends_on      = [google_project_service.run_api, google_project_service.container_registry_api]
  create_duration = "30s"
}

resource "google_cloud_run_service" "discord_bot" {
  name     = "discord-bot"
  location = var.region

  depends_on = [time_sleep.wait_30_seconds]

  template {
    metadata {
      annotations = {
        "autoscaling.knative.dev/maxScale"     = "1"
        "run.googleapis.com/cpu-throttling"    = "true"
        "run.googleapis.com/startup-cpu-boost" = "false"
      }
    }
    spec {
      containers {
        image = var.docker_image
        resources {
          limits = {
            cpu    = "1000m"
            memory = "256Mi"
          }
        }
        env {
          name  = "UPSTASH_REDIS_REST_URL"
          value = "https://${upstash_redis_database.redis-db.endpoint}"
        }
        env {
          name  = "UPSTASH_REDIS_REST_TOKEN"
          value = upstash_redis_database.redis-db.rest_token
        }
        env {
          name  = "DISCORD_TOKEN"
          value = var.discord_token
        }
        env {
          name  = "RESEND_API_KEY"
          value = var.resend_api_key
        }
      }
      container_concurrency = 10
      timeout_seconds       = 600
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }

  autogenerate_revision_name = true

}

resource "google_cloud_run_service_iam_member" "public_access" {
  service  = google_cloud_run_service.discord_bot.name
  location = google_cloud_run_service.discord_bot.location
  role     = "roles/run.invoker"
  member   = "allUsers"

  depends_on = [google_project_service.run_api]
}

