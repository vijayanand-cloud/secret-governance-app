
resource "azurerm_container_registry" "acr" {
  name                = var.acr_name
  resource_group_name = var.resource_group_name
  location            = var.location
  sku                 = "Basic"
  admin_enabled       = true
}

resource "azurerm_log_analytics_workspace" "law" {
  name                = "law-${var.container_app_env_name}"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

resource "azurerm_container_app_environment" "cae" {
  name                       = var.container_app_env_name
  location                   = var.location
  resource_group_name        = var.resource_group_name
  log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id

  # VNet Integration for Private Subnet
  infrastructure_subnet_id       = var.infrastructure_subnet_id
  internal_load_balancer_enabled = true
}

resource "azurerm_container_app" "app" {
  name                         = var.container_app_name
  container_app_environment_id = azurerm_container_app_environment.cae.id
  resource_group_name          = var.resource_group_name
  revision_mode                = "Single"
  
  secret {
    name  = "acr-password"
    value = azurerm_container_registry.acr.admin_password
  }

  registry {
    server               = azurerm_container_registry.acr.login_server
    username             = azurerm_container_registry.acr.admin_username
    password_secret_name = "acr-password"
  }

  template {
    container {
      name   = "langchain-agent"
      image  = "${azurerm_container_registry.acr.login_server}/secret-governance/langchain-agent:latest"
      cpu    = 0.5
      memory = "1.0Gi"

      env {
        name  = "KEY_VAULT_URL"
        value = var.key_vault_url
      }
      env {
        name  = "UAMI_CLIENT_ID"
        value = var.uami_client_id
      }
      env {
        name  = "MONITOR_MCP_URL"
        value = "http://localhost:8001/mcp"
      }
    }

    container {
      name   = "monitor-mcp"
      image  = "${azurerm_container_registry.acr.login_server}/secret-governance/monitor-mcp:latest"
      cpu    = 0.5
      memory = "1.0Gi"

      env {
        name  = "KEY_VAULT_URL"
        value = var.key_vault_url
      }
      env {
        name  = "UAMI_CLIENT_ID"
        value = var.uami_client_id
      }
    }
  }

  ingress {
    external_enabled = false
    target_port      = 8000
    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }
}
