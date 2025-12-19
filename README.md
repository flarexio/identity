# Identity [![Build](https://github.com/flarexio/identity/actions/workflows/build.yml/badge.svg)](https://github.com/flarexio/identity/actions/workflows/build.yml)

Identity is a scalable and decentralized microservice for user identity management.


# Prerequisites

NATS Server with JetStream: Refer to the official NATS website for installation instructions.

##  Dependency on NATS with JetStream

This project relies on NATS Server with JetStream functionality for its operations. Ensure that you have NATS Server with JetStream installed and running before using this project.

For installation instructions and details about NATS Server with JetStream, please refer to the official NATS website (https://nats.io).

## Installation

You can install Identity using one of the following methods:

### Binary

1. Clone the repository, navigate to the project directory, build, and install the binary using the following command:

   ```shell
   # clone the repository
   git clone https://github.com/flarexio/identity.git
   
   # navigate to the project directory
   cd identity
   
   # build and install
   go build -o $GOPATH/bin/identity cmd/identity/main.go
   ```

2. Copy the `config.yaml` file to the working directory. You can find an example configuration file in the project repository.
3. Set the necessary environment variables, such as `IDENTITY_PATH` and `IDENTITY_HTTP_PORT`, if required.
4. Run the installed binary to start the Identity microservice:

   ```shell
   identity
   ```

### Docker

1. Make sure you have Docker installed and running on your system.
2. Run the following command to start the Identity microservice using Docker:
3. Copy the `config.yaml` file to the working directory. You can find an example configuration file in the project repository.

   ```shell
   docker run -d -p 8080:8080 flarexio/identity:latest
   ```

   This command starts the Identity microservice in a Docker container, binds it to port 8080, and sets the `IDENTITY_PATH` and `IDENTITY_HTTP_PORT` environment variables. It also mounts the `config.yaml` file into the container at `/root/.identity/config.yaml`.

## License

This project is licensed under the [MIT License](LICENSE).
