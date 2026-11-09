
provider "aws" {
  profile = var.profile
  region  = var.region
}

provider "aws" {
  alias      = "plain_text_access_keys_provider"
  region     = "us-west-1"
  access_key = "<MASKED:api_key:2>"
  secret_key = "<MASKED:secret:3>"
}

terraform {
  backend "s3" {
    encrypt = true
  }
}
