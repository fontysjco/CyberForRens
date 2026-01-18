provider "azurerm" {
  features {}
  subscription_id = "80759b0c-6677-461b-babf-76487bdf3ed5"
}

resource "azurerm_resource_group" "rg" {
  name     = "rg-forensic-triage"
  location = "switzerlandnorth"
}

resource "azurerm_virtual_network" "vnet" {
  name                = "forensic-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_subnet" "subnet" {
  name                 = "internal-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.2.0/24"]
}

resource "azurerm_network_security_group" "nsg" {
  name                = "forensic-nsg"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  security_rule {
    name                       = "AllowSSH"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*" # Voor veiligheid later aanpassen naar je eigen IP!
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_interface" "nic" {
  name                = "forensic-nic"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.pip.id
  }
}

resource "azurerm_public_ip" "pip" {
  name                = "forensic-ip"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_linux_virtual_machine" "vm" {
  name                = "forensic-runner-vm"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  size                = "Standard_B2s" # Goedkoop maar krachtig genoeg voor Dissect
  admin_username      = "forensicadmin"
  network_interface_ids = [
    azurerm_network_interface.nic.id,
  ]

  admin_password                  = "FontysForensics2026!" # Gebruik een sterk wachtwoord!
  disable_password_authentication = false

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }
}

resource "azurerm_network_interface_security_group_association" "example" {
  network_interface_id      = azurerm_network_interface.nic.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}

resource "azurerm_storage_account" "forensic_storage" {
  name                     = "stforensicdata${random_string.suffix.result}" # Naam moet uniek zijn
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_storage_container" "images" {
  name                  = "evidence-images"
  storage_account_name  = azurerm_storage_account.forensic_storage.name
  container_access_type = "private" # Veiligheid voorop!
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}
