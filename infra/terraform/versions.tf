terraform {
  required_version = ">= 1.6"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "azurerm" {
  features {
    resource_group {
      # Allow `terraform destroy` even if Azure added resources (e.g. AMA artifacts) into the RG.
      prevent_deletion_if_contains_resources = false
    }
  }
  # null -> taken from ARM_SUBSCRIPTION_ID or the `az login` default subscription.
  subscription_id = var.subscription_id
}
