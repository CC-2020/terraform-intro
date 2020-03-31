# Introducción a Terraform

## Instalación
(Actuaización: 31 marzo 2020)

Desde la página de downloads de terraform (https://www.terraform.io/downloads.html) descarga la versión adecuada para tu sistema operativo
(descargaremos aquí la versión para Linux 64 bits)

```
$ wget https://releases.hashicorp.com/terraform/0.12.24/terraform_0.12.24_linux_amd64.zip
``` 

Descomprime el fichero usando unzip (si lo necesitas instala el paquete unzip):

```
$ sudo apt install unzip

$ unzip terraform_0.12.24_linux_amd64.zip
```

Mueve el fichero terraform ha una carpeta incluida en el PATH, por ejemplo a /usr/local/bin/:

```
$ sudo mv terraform /usr/local/bin
```

Prueba la instalación con:

```
$ terraform --version
Terraform v0.12.24
```

## Comandos Terraform

Muestra la ayuda sobre los comandos disponibles con:

```
$ terraform --help
Usage: terraform [-version] [-help] <command> [args]

The available commands for execution are listed below.
The most common, useful commands are shown first, followed by
less common or more advanced commands. If you're just getting
started with Terraform, stick with the common commands. For the
other commands, please read the help and docs before usage.

Common commands:
    apply              Builds or changes infrastructure
    console            Interactive console for Terraform interpolations
    destroy            Destroy Terraform-managed infrastructure
    env                Workspace management
    fmt                Rewrites config files to canonical format
    get                Download and install modules for the configuration
    graph              Create a visual graph of Terraform resources
    import             Import existing infrastructure into Terraform
    init               Initialize a Terraform working directory
    login              Obtain and save credentials for a remote host
    logout             Remove locally-stored credentials for a remote host
    output             Read an output from a state file
    plan               Generate and show an execution plan
    providers          Prints a tree of the providers used in the configuration
    refresh            Update local state file against real resources
    show               Inspect Terraform state or plan
    taint              Manually mark a resource for recreation
    untaint            Manually unmark a resource as tainted
    validate           Validates the Terraform files
    version            Prints the Terraform version
    workspace          Workspace management

All other commands:
    0.12upgrade        Rewrites pre-0.12 module source code for v0.12
    debug              Debug output management (experimental)
    force-unlock       Manually unlock the terraform state
    push               Obsolete command for Terraform Enterprise legacy (v1)
    state              Advanced state management
```


## Aspectos básicos. Documentación

La infracestructura con Terraform se crea mediante un conjunto de ficheros (.tf),
llamados ficheros de configuración, que incluyen: identificación del proveedor o proveedores,
creación de recursos y definición de variables, outputs, etc.

Puedes obtener información sobre los proveedores en:

https://www.terraform.io/docs/providers/index.html

Dentro de cada proveedor puedes consultar la documentación para crear los recursos disponibles:

Para AWS: https://www.terraform.io/docs/providers/aws/index.html

Para GCP: https://www.terraform.io/docs/providers/google/index.html

En la documentacióm para cada recurso de un proveedor, tenemos los "Data source" con la información
que podemos utilizar de cada recurso y los "Resources" con los parámetros y los atributos para crearlo.
En ambos casos, tenemos varios ejemplos.

Puedes consultar más información sobre otros elementos:

Variables: https://www.terraform.io/docs/configuration/variables.html

Outputs: https://www.terraform.io/docs/configuration/outputs.html

Funciones: https://www.terraform.io/docs/configuration/functions.html

Módulos: https://www.terraform.io/docs/configuration/modules.html


## Ejemplo

En el siguiente ejemplo usaremos AWS:

### Asignando el proveedor

```
provider "aws" {
  region     = "us-east-1"
  
  # ~/.aws/credentials
  profile = "default"

  # Alternativamente, aunque desaconsejado, se pueden incluir los valores aquí
  # access_key = "ACCESSKEY"
  # secret_key = "SECRETKEY"
  # token      = "SESSIONTOKEN"
}
```


### Crear una SSH key pair 

```
resource "aws_key_pair" "sshkeyt" {
  key_name   = "sshkeyt"
  public_key = file("~/.ssh/id_rsa.pub")
}
```

### Crear una grupo de seguridad

Este grupo de seguridad permite tráfico SSH de entrada y todo el de salida

```
resource "aws_security_group" "allow_ssh" {
  name        = "allow_ssh"
  description = "Allow SSH inbound traffic"

  ingress {
    description = "SSH from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [ "0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ALLOW_SSH"
  }
}
```
### Crear una instancia 

Esta instancia tendrá la Key pair y el grupo de seguridad creadas anteriormente

```
resource "aws_instance" "web" {
  ami           = "ami-07ebfd5b3428b6f4d"
  instance_type = "t2.micro"
  key_name = aws_key_pair.sshkeyt.key_name
  security_groups = [ aws_security_group.allow_ssh.name ]

  tags = {
    Name = "HelloWorld"
  }
}
```

## Iniciar Terraform

Antes de utilizar terraform es necesario inicializarlo para que se descargue los necesario
para trabajar con los proveedores y elementos definidos en los ficheros de configuración (.tf)

```
$ terraform init


Initializing the backend...

Initializing provider plugins...
- Checking for available provider plugins...
- Downloading plugin for provider "aws" (hashicorp/aws) 2.55.0...

The following providers do not have any version constraints in configuration,
so the latest version was installed.

To prevent automatic upgrades to new major versions that may contain breaking
changes, it is recommended to add version = "..." constraints to the
corresponding provider blocks in configuration, with the constraint strings
suggested below.

* provider.aws: version = "~> 2.55"

Terraform has been successfully initialized!

You may now begin working with Terraform. Try running "terraform plan" to see
any changes that are required for your infrastructure. All Terraform commands
should now work.

If you ever set or change modules or backend configuration for Terraform,
rerun this command to reinitialize your working directory. If you forget, other
commands will detect it and remind you to do so if necessary.
```


## Planear la infracestructura

```
$ terraform plan

Refreshing Terraform state in-memory prior to plan...
The refreshed state will be used to calculate this plan, but will not be
persisted to local or remote state storage.


------------------------------------------------------------------------

An execution plan has been generated and is shown below.
Resource actions are indicated with the following symbols:
  + create

Terraform will perform the following actions:

  # aws_instance.web will be created
  + resource "aws_instance" "web" {
      + ami                          = "ami-07ebfd5b3428b6f4d"
      + arn                          = (known after apply)
      + associate_public_ip_address  = (known after apply)
      + availability_zone            = (known after apply)
      + cpu_core_count               = (known after apply)
      + cpu_threads_per_core         = (known after apply)
      + get_password_data            = false
      + host_id                      = (known after apply)
      + id                           = (known after apply)
      + instance_state               = (known after apply)
      + instance_type                = "t2.micro"
      + ipv6_address_count           = (known after apply)
      + ipv6_addresses               = (known after apply)
      + key_name                     = "sshkeyt"
      + network_interface_id         = (known after apply)
      + password_data                = (known after apply)
      + placement_group              = (known after apply)
      + primary_network_interface_id = (known after apply)
      + private_dns                  = (known after apply)
      + private_ip                   = (known after apply)
      + public_dns                   = (known after apply)
      + public_ip                    = (known after apply)
      + security_groups              = [
          + "allow_ssh",
        ]
      + source_dest_check            = true
      + subnet_id                    = (known after apply)
      + tags                         = {
          + "Name" = "HelloWorld"
        }
      + tenancy                      = (known after apply)
      + volume_tags                  = (known after apply)
      + vpc_security_group_ids       = (known after apply)

      + ebs_block_device {
          + delete_on_termination = (known after apply)
          + device_name           = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + snapshot_id           = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }

      + ephemeral_block_device {
          + device_name  = (known after apply)
          + no_device    = (known after apply)
          + virtual_name = (known after apply)
        }

      + metadata_options {
          + http_endpoint               = (known after apply)
          + http_put_response_hop_limit = (known after apply)
          + http_tokens                 = (known after apply)
        }

      + network_interface {
          + delete_on_termination = (known after apply)
          + device_index          = (known after apply)
          + network_interface_id  = (known after apply)
        }

      + root_block_device {
          + delete_on_termination = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }
    }

  # aws_key_pair.sshkeyt will be created
  + resource "aws_key_pair" "sshkeyt" {
      + fingerprint = (known after apply)
      + id          = (known after apply)
      + key_name    = "sshkeyt"
      + key_pair_id = (known after apply)
      + public_key  = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDwNYRwR5CZrOgjhy2RtrJB5Dx6S0XiWxrCRou+yMQ2jcHdBgHqNv/9quUztiyZLwl/tH4fYhfyYVzQO4Pw4tTU2XNiOSHW2yE6Ht6lIH54lM+MbU+MsHQOSAV72lcCXZ0DyJ/Kbt0MUkFZQtooltCkoYn1mOCLYxrx5BmC7E5nW1G3X5RDvpT5gPV2OjxEITxC04X+cXz/A5lL2pb1010XtpeAMHJT4gxFiI1s8VLwrD2vx2DO296yWibeLE9qWQC7YxeRv1VrMF+qirJc3yP74l736DNah8QRvdSv6AUNOesrAgpFO5UP9MQW861db/QwNxsI28VO0hrEoN+WPw1r ec2-user@ip-172-31-82-119"
    }

  # aws_security_group.allow_ssh will be created
  + resource "aws_security_group" "allow_ssh" {
      + arn                    = (known after apply)
      + description            = "Allow SSH inbound traffic"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "SSH from VPC"
              + from_port        = 22
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 22
            },
        ]
      + name                   = "allow_ssh"
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name" = "ALLOW_SSH"
        }
      + vpc_id                 = (known after apply)
    }

Plan: 3 to add, 0 to change, 0 to destroy.

------------------------------------------------------------------------

Note: You didn't specify an "-out" parameter to save this plan, so Terraform
can't guarantee that exactly these actions will be performed if
"terraform apply" is subsequently run.
```



## Aplica la infracestructura

```
$ terraform apply

An execution plan has been generated and is shown below.
Resource actions are indicated with the following symbols:
  + create

Terraform will perform the following actions:

  # aws_instance.web will be created
  + resource "aws_instance" "web" {
      + ami                          = "ami-07ebfd5b3428b6f4d"
      + arn                          = (known after apply)
      + associate_public_ip_address  = (known after apply)
      + availability_zone            = (known after apply)
      + cpu_core_count               = (known after apply)
      + cpu_threads_per_core         = (known after apply)
      + get_password_data            = false
      + host_id                      = (known after apply)
      + id                           = (known after apply)
      + instance_state               = (known after apply)
      + instance_type                = "t2.micro"
      + ipv6_address_count           = (known after apply)
      + ipv6_addresses               = (known after apply)
      + key_name                     = "sshkeyt"
      + network_interface_id         = (known after apply)
      + password_data                = (known after apply)
      + placement_group              = (known after apply)
      + primary_network_interface_id = (known after apply)
      + private_dns                  = (known after apply)
      + private_ip                   = (known after apply)
      + public_dns                   = (known after apply)
      + public_ip                    = (known after apply)
      + security_groups              = [
          + "allow_ssh",
        ]
      + source_dest_check            = true
      + subnet_id                    = (known after apply)
      + tags                         = {
          + "Name" = "HelloWorld"
        }
      + tenancy                      = (known after apply)
      + volume_tags                  = (known after apply)
      + vpc_security_group_ids       = (known after apply)

      + ebs_block_device {
          + delete_on_termination = (known after apply)
          + device_name           = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + snapshot_id           = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }

      + ephemeral_block_device {
          + device_name  = (known after apply)
          + no_device    = (known after apply)
          + virtual_name = (known after apply)
        }

      + metadata_options {
          + http_endpoint               = (known after apply)
          + http_put_response_hop_limit = (known after apply)
          + http_tokens                 = (known after apply)
        }

      + network_interface {
          + delete_on_termination = (known after apply)
          + device_index          = (known after apply)
          + network_interface_id  = (known after apply)
        }

      + root_block_device {
          + delete_on_termination = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }
    }

  # aws_key_pair.sshkeyt will be created
  + resource "aws_key_pair" "sshkeyt" {
      + fingerprint = (known after apply)
      + id          = (known after apply)
      + key_name    = "sshkeyt"
      + key_pair_id = (known after apply)
      + public_key  = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDwNYRwR5CZrOgjhy2RtrJB5Dx6S0XiWxrCRou+yMQ2jcHdBgHqNv/9quUztiyZLwl/tH4fYhfyYVzQO4Pw4tTU2XNiOSHW2yE6Ht6lIH54lM+MbU+MsHQOSAV72lcCXZ0DyJ/Kbt0MUkFZQtooltCkoYn1mOCLYxrx5BmC7E5nW1G3X5RDvpT5gPV2OjxEITxC04X+cXz/A5lL2pb1010XtpeAMHJT4gxFiI1s8VLwrD2vx2DO296yWibeLE9qWQC7YxeRv1VrMF+qirJc3yP74l736DNah8QRvdSv6AUNOesrAgpFO5UP9MQW861db/QwNxsI28VO0hrEoN+WPw1r ec2-user@ip-172-31-82-119"
    }

  # aws_security_group.allow_ssh will be created
  + resource "aws_security_group" "allow_ssh" {
      + arn                    = (known after apply)
      + description            = "Allow SSH inbound traffic"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "SSH from VPC"
              + from_port        = 22
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 22
            },
        ]
      + name                   = "allow_ssh"
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name" = "ALLOW_SSH"
        }
      + vpc_id                 = (known after apply)
    }

Plan: 3 to add, 0 to change, 0 to destroy.

Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.
                                               .<< Introduce yes >>
  Enter a value: yes        <-----------------´

aws_key_pair.sshkeyt: Creating...
aws_security_group.allow_ssh: Creating...
aws_key_pair.sshkeyt: Creation complete after 0s [id=sshkeyt]
aws_security_group.allow_ssh: Creation complete after 1s [id=sg-0e8abe1c8e1bacafd]
aws_instance.web: Creating...
aws_instance.web: Still creating... [10s elapsed]
aws_instance.web: Still creating... [20s elapsed]
aws_instance.web: Still creating... [30s elapsed]
aws_instance.web: Still creating... [40s elapsed]
aws_instance.web: Still creating... [50s elapsed]
aws_instance.web: Creation complete after 52s [id=i-0fd9cfb301e1ec897]

Apply complete! Resources: 3 added, 0 changed, 0 destroyed.

```


## Destruye la infraestructura

```
$ terraform destroy

aws_security_group.allow_ssh: Refreshing state... [id=sg-0e8abe1c8e1bacafd]
aws_key_pair.sshkeyt: Refreshing state... [id=sshkeyt]
aws_instance.web: Refreshing state... [id=i-0fd9cfb301e1ec897]

An execution plan has been generated and is shown below.
Resource actions are indicated with the following symbols:
  - destroy

Terraform will perform the following actions:

  # aws_instance.web will be destroyed
  - resource "aws_instance" "web" {
      - ami                          = "ami-07ebfd5b3428b6f4d" -> null
      - arn                          = "arn:aws:ec2:us-east-1:139527570839:instance/i-0fd9cfb301e1ec897" -> null
      - associate_public_ip_address  = true -> null
      - availability_zone            = "us-east-1a" -> null
      - cpu_core_count               = 1 -> null
      - cpu_threads_per_core         = 1 -> null
      - disable_api_termination      = false -> null
      - ebs_optimized                = false -> null
      - get_password_data            = false -> null
      - hibernation                  = false -> null
      - id                           = "i-0fd9cfb301e1ec897" -> null
      - instance_state               = "running" -> null
      - instance_type                = "t2.micro" -> null
      - ipv6_address_count           = 0 -> null
      - ipv6_addresses               = [] -> null
      - key_name                     = "sshkeyt" -> null
      - monitoring                   = false -> null
      - primary_network_interface_id = "eni-0699d9722b0bd22a5" -> null
      - private_dns                  = "ip-172-31-35-47.ec2.internal" -> null
      - private_ip                   = "172.31.35.47" -> null
      - public_dns                   = "ec2-54-211-98-247.compute-1.amazonaws.com" -> null
      - public_ip                    = "54.211.98.247" -> null
      - security_groups              = [
          - "allow_ssh",
        ] -> null
      - source_dest_check            = true -> null
      - subnet_id                    = "subnet-112e204d" -> null
      - tags                         = {
          - "Name" = "HelloWorld"
        } -> null
      - tenancy                      = "default" -> null
      - volume_tags                  = {} -> null
      - vpc_security_group_ids       = [
          - "sg-0e8abe1c8e1bacafd",
        ] -> null

      - credit_specification {
          - cpu_credits = "standard" -> null
        }

      - metadata_options {
          - http_endpoint               = "enabled" -> null
          - http_put_response_hop_limit = 1 -> null
          - http_tokens                 = "optional" -> null
        }

      - root_block_device {
          - delete_on_termination = true -> null
          - encrypted             = false -> null
          - iops                  = 100 -> null
          - volume_id             = "vol-09618c5a31eb71050" -> null
          - volume_size           = 8 -> null
          - volume_type           = "gp2" -> null
        }
    }

  # aws_key_pair.sshkeyt will be destroyed
  - resource "aws_key_pair" "sshkeyt" {
      - fingerprint = "cb:90:9d:b8:53:ed:fb:3d:0a:b2:19:c6:9c:0b:8e:aa" -> null
      - id          = "sshkeyt" -> null
      - key_name    = "sshkeyt" -> null
      - key_pair_id = "key-094f138411cabb2c6" -> null
      - public_key  = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDwNYRwR5CZrOgjhy2RtrJB5Dx6S0XiWxrCRou+yMQ2jcHdBgHqNv/9quUztiyZLwl/tH4fYhfyYVzQO4Pw4tTU2XNiOSHW2yE6Ht6lIH54lM+MbU+MsHQOSAV72lcCXZ0DyJ/Kbt0MUkFZQtooltCkoYn1mOCLYxrx5BmC7E5nW1G3X5RDvpT5gPV2OjxEITxC04X+cXz/A5lL2pb1010XtpeAMHJT4gxFiI1s8VLwrD2vx2DO296yWibeLE9qWQC7YxeRv1VrMF+qirJc3yP74l736DNah8QRvdSv6AUNOesrAgpFO5UP9MQW861db/QwNxsI28VO0hrEoN+WPw1r ec2-user@ip-172-31-82-119" -> null
      - tags        = {} -> null
    }

  # aws_security_group.allow_ssh will be destroyed
  - resource "aws_security_group" "allow_ssh" {
      - arn                    = "arn:aws:ec2:us-east-1:139527570839:security-group/sg-0e8abe1c8e1bacafd" -> null
      - description            = "Allow SSH inbound traffic" -> null
      - egress                 = [
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - description      = ""
              - from_port        = 0
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "-1"
              - security_groups  = []
              - self             = false
              - to_port          = 0
            },
        ] -> null
      - id                     = "sg-0e8abe1c8e1bacafd" -> null
      - ingress                = [
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - description      = "SSH from VPC"
              - from_port        = 22
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "tcp"
              - security_groups  = []
              - self             = false
              - to_port          = 22
            },
        ] -> null
      - name                   = "allow_ssh" -> null
      - owner_id               = "139527570839" -> null
      - revoke_rules_on_delete = false -> null
      - tags                   = {
          - "Name" = "ALLOW_SSH"
        } -> null
      - vpc_id                 = "vpc-6dc99717" -> null
    }

Plan: 0 to add, 0 to change, 3 to destroy.

Do you really want to destroy all resources?
  Terraform will destroy all your managed infrastructure, as shown above.
  There is no undo. Only 'yes' will be accepted to confirm.

  Enter a value: yes

aws_instance.web: Destroying... [id=i-0fd9cfb301e1ec897]
aws_instance.web: Still destroying... [id=i-0fd9cfb301e1ec897, 10s elapsed]
aws_instance.web: Still destroying... [id=i-0fd9cfb301e1ec897, 20s elapsed]
aws_instance.web: Destruction complete after 29s
aws_key_pair.sshkeyt: Destroying... [id=sshkeyt]
aws_security_group.allow_ssh: Destroying... [id=sg-0e8abe1c8e1bacafd]
aws_key_pair.sshkeyt: Destruction complete after 1s
aws_security_group.allow_ssh: Destruction complete after 1s

Destroy complete! Resources: 3 destroyed.
```





