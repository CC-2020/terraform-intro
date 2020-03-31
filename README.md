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
```


## Planear la infracestructura

```
$ terraform plan
```

## Aplica la infracestructura

```
$ terraform plan
```

## Destruye la infraestructura

```
$ terraform destroy
```




