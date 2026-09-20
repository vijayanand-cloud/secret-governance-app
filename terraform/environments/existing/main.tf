terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

variable "location" { default = "South India" }
variable "resource_group_name" { default = "Foundry-Project" }
variable "key_vault_name" { default = "kv-secret-monitor" }

resource "azurerm_resource_group" "rg" {
  name     = var.resource_group_name
  location = var.location
}

# Create a VNet and Subnet specifically for the Container Apps
resource "azurerm_virtual_network" "vnet" {
  name                = "vnet-secret-governance"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  address_space       = ["10.0.0.0/16"]
}

resource "azurerm_subnet" "snet" {
  name                 = "snet-containerapps"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.0.0/23"]
}

# Data blocks to fetch existing resources
data "azurerm_key_vault" "kv" {
  name                = var.key_vault_name
  resource_group_name = azurerm_resource_group.rg.name
}

data "azurerm_user_assigned_identity" "uami" {
  name                = "uami-secret-governance"
  resource_group_name = azurerm_resource_group.rg.name
}

module "secret_governance" {
  source = "../../modules/secret_governance"

  location                 = azurerm_resource_group.rg.location
  resource_group_name      = azurerm_resource_group.rg.name
  acr_name                 = "acrsecretmonitor0103"
  container_app_env_name   = "cae-secret-monitor"
  container_app_name       = "secret-governance-v2"
  infrastructure_subnet_id = azurerm_subnet.snet.id

  # Existing Identity and Vault
  key_vault_url  = data.azurerm_key_vault.kv.vault_uri
  uami_client_id = data.azurerm_user_assigned_identity.uami.client_id

  # Variables that must be provided via terraform.tfvars or env vars
  openai_api_base              = var.openai_api_base
  openai_api_key               = var.openai_api_key
  openai_api_version           = var.openai_api_version
  azure_openai_deployment_name = var.azure_openai_deployment_name
}

variable "openai_api_base" { type = string }
variable "openai_api_key" {
  type      = string
  sensitive = true
}
variable "openai_api_version" {
  type    = string
  default = "2023-05-15"
}
variable "azure_openai_deployment_name" {
  type    = string
  default = "gpt-4"
}
