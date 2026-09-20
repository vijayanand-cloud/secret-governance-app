variable "location" {
  type    = string
  default = "South India"
}

variable "resource_group_name" {
  type = string
}

variable "acr_name" {
  type = string
}

variable "container_app_env_name" {
  type = string
}

variable "container_app_name" {
  type = string
}

variable "infrastructure_subnet_id" {
  description = "The ID of the Subnet where the Container App Environment should be created (for private VNet integration)."
  type        = string
}

variable "key_vault_url" {
  type = string
}

variable "uami_client_id" {
  type = string
}

variable "openai_api_base" {
  type = string
}

variable "openai_api_key" {
  type      = string
  sensitive = true
}

variable "openai_api_version" {
  type    = string
  default = "2023-05-15"
}

variable "azure_openai_deployment_name" {
  type = string
}

variable "monitor_api_base_url" {
  type    = string
  default = "http://localhost:8001"
}
