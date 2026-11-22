terraform {
  backend "s3" {
    bucket       = "acme-health-tfstate-388301161877"
    key          = "cgep-app-starter/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}
