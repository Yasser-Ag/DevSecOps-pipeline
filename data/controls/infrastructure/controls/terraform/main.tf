resource "aws_security_group" "t01" {
  name = "development-t01"
  description = "Static development control"
  vpc_id = "vpc-development"
  ingress {
    description = "Declared ingress"
    protocol = "tcp"
    from_port = 22
    to_port = 22
    cidr_blocks = ["0.0.0.0/0"]
    ipv6_cidr_blocks = []
  }
}

resource "aws_security_group" "t02" {
  name = "development-t02"
  description = "Static development control"
  vpc_id = "vpc-development"
  ingress {
    description = "Declared ingress"
    protocol = "tcp"
    from_port = 22
    to_port = 22
    cidr_blocks = ["10.12.0.0/16"]
    ipv6_cidr_blocks = []
  }
}

resource "aws_security_group" "t03" {
  name = "development-t03"
  description = "Static development control"
  vpc_id = "vpc-development"
  ingress {
    description = "Declared ingress"
    protocol = "tcp"
    from_port = 80
    to_port = 80
    cidr_blocks = ["0.0.0.0/0"]
    ipv6_cidr_blocks = []
  }
}

resource "aws_security_group" "t04a" {
  name = "development-t04a"
  description = "Static development control"
  vpc_id = "vpc-development"
  ingress {
    description = "Declared ingress"
    protocol = "tcp"
    from_port = 22
    to_port = 22
    cidr_blocks = ["0.0.0.0/0"]
    ipv6_cidr_blocks = []
  }
}

resource "aws_security_group" "t04b" {
  name = "development-t04b"
  description = "Static development control"
  vpc_id = "vpc-development"
  ingress {
    description = "Declared ingress"
    protocol = "tcp"
    from_port = 22
    to_port = 22
    cidr_blocks = ["0.0.0.0/0"]
    ipv6_cidr_blocks = []
  }
}

resource "aws_security_group" "t05" {
  name = "development-t05"
  description = "Static development control"
  vpc_id = "vpc-development"
  ingress {
    description = "Declared ingress"
    protocol = "tcp"
    from_port = 22
    to_port = 22
    cidr_blocks = []
    ipv6_cidr_blocks = ["::/0"]
  }
}

resource "aws_security_group" "t06" {
  name = "development-t06"
  description = "Static development control"
  vpc_id = "vpc-development"
  ingress {
    description = "Declared ingress"
    protocol = "tcp"
    from_port = 22
    to_port = 22
    cidr_blocks = []
    ipv6_cidr_blocks = ["fd00::/64"]
  }
}
