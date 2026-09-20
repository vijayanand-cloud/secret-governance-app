variable "location" {
  description = "Azure region for resources"
  type        = string
  default     = "South India"
}

variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
  default     = "Foundry-Project"
}

variable "acr_name" {
  description = "Name of the Azure Container Registry"
  type        = string
  default     = "acrsecretmonitor0103"
}

variable "container_app_env_name" {
  description = "Name of the Container Apps Environment"
  type        = string
  default     = "cae-secret-monitor"
}

variable "container_app_name" {
  description = "Name of the Container App"
  type        = string
  default     = "secret-governance-v2"
}
