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
variable "resource_group_name" { default = "Foundry-Project-New" }

resource "azurerm_resource_group" "rg" {
  name     = var.resource_group_name
  location = var.location
}

# VNet and Subnet
resource "azurerm_virtual_network" "vnet" {
  name                = "vnet-secret-gov-new"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  address_space       = ["10.1.0.0/16"]
}

resource "azurerm_subnet" "snet" {
  name                 = "snet-containerapps-new"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.1.0.0/23"]
  delegation {
    name = "Microsoft.App.environments"
    service_delegation {
      name    = "Microsoft.App/environments"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

# Identity
resource "azurerm_user_assigned_identity" "uami" {
  name                = "uami-secret-gov-new"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

data "azurerm_client_config" "current" {}

# Key Vault
resource "azurerm_key_vault" "kv" {
  name                       = "kv-secgov-new-${random_string.suffix.result}"
  location                   = azurerm_resource_group.rg.location
  resource_group_name        = azurerm_resource_group.rg.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  purge_protection_enabled   = false
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

# Key Vault Access Policies
resource "azurerm_key_vault_access_policy" "uami_policy" {
  key_vault_id = azurerm_key_vault.kv.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_user_assigned_identity.uami.principal_id

  secret_permissions = ["Get", "List"]
}

resource "azurerm_key_vault_access_policy" "deployer_policy" {
  key_vault_id = azurerm_key_vault.kv.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = data.azurerm_client_config.current.object_id

  secret_permissions = ["Get", "List", "Set", "Delete"]
}

# Key Vault Secrets Setup (Populated from Variables)
variable "jira_api_token" {
  type      = string
  sensitive = true
}
variable "jira_user_email" { type = string }
variable "graph_tenant_id" { type = string }

resource "azurerm_key_vault_secret" "jira_token" {
  name         = "JIRA-API-TOKEN"
  value        = var.jira_api_token
  key_vault_id = azurerm_key_vault.kv.id
  depends_on   = [azurerm_key_vault_access_policy.deployer_policy]
}
resource "azurerm_key_vault_secret" "jira_email" {
  name         = "JIRA-USER-EMAIL"
  value        = var.jira_user_email
  key_vault_id = azurerm_key_vault.kv.id
  depends_on   = [azurerm_key_vault_access_policy.deployer_policy]
}
resource "azurerm_key_vault_secret" "graph_tenant" {
  name         = "GRAPH-TENANT-ID"
  value        = var.graph_tenant_id
  key_vault_id = azurerm_key_vault.kv.id
  depends_on   = [azurerm_key_vault_access_policy.deployer_policy]
}

# Azure OpenAI Service
resource "azurerm_cognitive_account" "openai" {
  name                = "openai-secgov-${random_string.suffix.result}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  kind                = "OpenAI"
  sku_name            = "S0"
}

resource "azurerm_cognitive_deployment" "gpt4" {
  name                 = "gpt-4"
  cognitive_account_id = azurerm_cognitive_account.openai.id
  model {
    format  = "OpenAI"
    name    = "gpt-4"
    version = "0613"
  }
  scale {
    type = "Standard"
  }
}

# The Core Module
module "secret_governance" {
  source = "../../modules/secret_governance"

  location                 = azurerm_resource_group.rg.location
  resource_group_name      = azurerm_resource_group.rg.name
  acr_name                 = "acrnewsecgov${random_string.suffix.result}"
  container_app_env_name   = "cae-secret-monitor-new"
  container_app_name       = "secret-governance-v2-new"
  infrastructure_subnet_id = azurerm_subnet.snet.id

  # New Identity and Vault
  key_vault_url  = azurerm_key_vault.kv.vault_uri
  uami_client_id = azurerm_user_assigned_identity.uami.client_id

  # Azure OpenAI connection
  
  
  
  
}

resource "azurerm_key_vault_secret" "aoai_endpoint" {
  name         = "AZURE-OPENAI-ENDPOINT"
  value        = azurerm_cognitive_account.openai.endpoint
  key_vault_id = azurerm_key_vault.kv.id
  depends_on   = [azurerm_key_vault_access_policy.deployer_policy]
}

resource "azurerm_key_vault_secret" "aoai_key" {
  name         = "AZURE-OPENAI-API-KEY"
  value        = azurerm_cognitive_account.openai.primary_access_key
  key_vault_id = azurerm_key_vault.kv.id
  depends_on   = [azurerm_key_vault_access_policy.deployer_policy]
}

resource "azurerm_key_vault_secret" "aoai_deployment" {
  name         = "AZURE-OPENAI-DEPLOYMENT-NAME"
  value        = azurerm_cognitive_deployment.gpt4.name
  key_vault_id = azurerm_key_vault.kv.id
  depends_on   = [azurerm_key_vault_access_policy.deployer_policy]
}

