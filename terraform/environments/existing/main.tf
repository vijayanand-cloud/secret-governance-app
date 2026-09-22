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
variable "key_vault_name" { default = "kv-secret-monitor-0103" }

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
  delegation {
    name = "Microsoft.App.environments"
    service_delegation {
      name    = "Microsoft.App/environments"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

# Data blocks to fetch existing resources
data "azurerm_key_vault" "kv" {
  name                = var.key_vault_name
  resource_group_name = azurerm_resource_group.rg.name
}

data "azurerm_user_assigned_identity" "uami" {
  name                = "uami-secret-monitor"
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
}









