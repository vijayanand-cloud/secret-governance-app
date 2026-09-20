
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
  type        = string
}

variable "key_vault_url" {
  type = string
}

variable "uami_client_id" {
  type = string
}
