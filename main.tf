terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.27"
    }
  }

  required_version = ">= 0.14.9"
}

provider "aws" {
  profile = "attilio-test"
  region  = "eu-central-1"
}

# NodeGroup IAM Role

# arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy
# arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy
# arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly
#
# Resource:
# https://registry.terraform.io/providers/hashicorp/aws/2.34.0/docs/guides/eks-getting-started


resource "aws_iam_role" "demo-cluster" {
  name = "terraform-eks-demo-cluster"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "eks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "demo-cluster-AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.demo-cluster.name
}

resource "aws_iam_role_policy_attachment" "demo-cluster-AmazonEKSServicePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
  role       = aws_iam_role.demo-cluster.name
}

# NodeGroup IAM Role

# arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy
# arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy
# arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly
#
# Resource:
# https://registry.terraform.io/providers/hashicorp/aws/2.34.0/docs/guides/eks-getting-started


resource "aws_iam_role" "demo-node" {
  name = "terraform-eks-demo-node"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "demo-node-AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.demo-node.name
}

resource "aws_iam_role_policy_attachment" "demo-node-AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.demo-node.name
}

resource "aws_iam_role_policy_attachment" "demo-node-AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.demo-node.name
}

resource "aws_iam_instance_profile" "demo-node" {
  name = "terraform-eks-demo"
  role = aws_iam_role.demo-node.name
}

# Aggiunta CIDR 

# CIDR 10.246.0.0/16 alla vpc-090fe97ea9f88804a / vpc-cicd-noprod (10.127.250.128/26)
#
# Resource:
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_ipv4_cidr_block_association

resource "aws_vpc" "main" {
  cidr_block = "10.127.250.128/26"
}

resource "aws_vpc_ipv4_cidr_block_association" "secondary_cidr" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.246.0.0/16"
}


# Creazione due subnet
#
# subnet-082720a7857fc7c1e / subnet-cicd-pod-az1: 10.246.0.0/17
# subnet-0f35e993623a680a7 / subnet-cicd-pod-az2: 10.246.128.0/17
#
# Resource:
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/subnet

resource "aws_subnet" "subnet-cicd-pod-az1" {
  vpc_id     = aws_vpc_ipv4_cidr_block_association.secondary_cidr.vpc_id
  cidr_block = "10.246.0.0/17"
}

resource "aws_subnet" "subnet-cicd-pod-az2" {
  vpc_id     = aws_vpc_ipv4_cidr_block_association.secondary_cidr.vpc_id
  cidr_block = "10.246.128.0/17"
}


# Creazione EKS
#
# Private
# ServiceIpv4Cidr: 10.247.0.0/16
# subnet per pod (https://docs.aws.amazon.com/eks/latest/userguide/cni-custom-network.html)
#   - subnet-cicd-pod-az1
#   - subnet-cicd-pod-az2
#
# Resource:
# https://registry.terraform.io/modules/terraform-aws-modules/eks/aws/latest

data "aws_eks_cluster" "eks" {
  name = module.eks.cluster_id
}

data "aws_eks_cluster_auth" "eks" {
  name = module.eks.cluster_id
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.eks.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.eks.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.eks.token
}


module "eks" {
  source = "terraform-aws-modules/eks/aws"

  cluster_version = "1.21"
  cluster_name    = "SecDevOps-cluster"
  vpc_id          = aws_vpc_ipv4_cidr_block_association.secondary_cidr.vpc_id
  subnets         = [aws_subnet.subnet-cicd-pod-az1.id, aws_subnet.subnet-cicd-pod-az2.id]

}

resource "tls_private_key" "tls" {
  algorithm = "RSA"
}

module "key_pair" {
  source = "terraform-aws-modules/key-pair/aws"

  key_name   = "deployer-one"
  public_key = tls_private_key.tls.public_key_openssh
}

#---------

resource "aws_eks_node_group" "example" {
  cluster_name    = "SecDevOps-cluster"
  node_group_name = "example"
  node_role_arn   = aws_iam_role.demo-node.arn
  subnet_ids      = [aws_subnet.subnet-cicd-pod-az1.id, aws_subnet.subnet-cicd-pod-az2.id]

  disk_size = 20 # come Default

  scaling_config {
    desired_size = 3
    max_size     = 3
    min_size     = 3
  }

  update_config {
    max_unavailable = 1
  }

  #remote_access {
  #ec2_ssh_key = module.key_pair.public_key
  #}

  # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
  # Otherwise, EKS will not be able to properly delete EC2 Instances and Elastic Network Interfaces.
  depends_on = [
    aws_iam_role_policy_attachment.demo-node-AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.demo-node-AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.demo-node-AmazonEC2ContainerRegistryReadOnly
  ]
}
