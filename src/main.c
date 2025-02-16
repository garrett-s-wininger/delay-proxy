#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#define LOOPBACK "127.0.0.1"
#define TRANSFER_BUFFER_SIZE 1024

void print_usage(void) {
  printf("Inject delays in network communications between two TCP endpoints\n\n");
  printf("Usage:\n");
  printf(" %-20s - Print this usage information\n", "proxy -h");
  printf(" %-20s - Run the proxy with the provided setings\n\n", "proxy OPTIONS");
  printf("Options:\n");
  printf(" %-20s - Listen on the specified IPv4 address\n", "-l ADDRESS");
  printf(" %-20s - Remote IPv4 address to proxy connection data to\n", "-r ADDRESS");
}

int main(int argc, char** argv) {
  int opt;
  uint16_t local_port = 8081;
  uint16_t remote_port = 8080;

  // Don't bother with validation here on the known loopback address
  struct in_addr local_ip, remote_ip = { 0 };
  inet_pton(AF_INET, LOOPBACK, &local_ip);
  inet_pton(AF_INET, LOOPBACK, &remote_ip);

  char friendly_ip[INET_ADDRSTRLEN];

  // Argument parsing
  while ((opt = getopt(argc, argv, "hl:r:")) != -1) {
    switch (opt) {
      case 'h':
        print_usage();
        return 0;
      case 'l':
        // TODO(Garrett): Handle attached port information
        if (inet_pton(AF_INET, optarg, &local_ip) == 0) {
          printf("[ERROR] Local IP %s is not a valid IPv4 address\n", optarg);
          exit(EXIT_FAILURE);
        }

        break;
      case 'r':
        // TODO(Garrett): Handle attached port information
        if (inet_pton(AF_INET, optarg, &remote_ip) == 0) {
          printf("[ERROR] Remote IP %s is not a valid IPv4 address\n", optarg);
          exit(EXIT_FAILURE);
        }

        break;
      default:
        printf("\n");
        print_usage();
        exit(EXIT_FAILURE);
    }
  }

  printf("[INFO] Running as PID %d\n", getpid());

  // Create base of local listening socket
  int source_sock = socket(AF_INET, SOCK_STREAM, 0);

  if (source_sock == -1) {
    perror("[ERROR] Unable to create socket for incoming connection");
    exit(EXIT_FAILURE);
  }

  int sock_opt = 1;

  if (setsockopt(source_sock, SOL_SOCKET, SO_REUSEPORT | SO_REUSEADDR, &sock_opt, sizeof(sock_opt)) == -1) {
    perror("[ERROR] Unable to set appropiate options for the incoming socket");
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in address = {
    .sin_addr = local_ip,
    .sin_family = AF_INET,
    .sin_port = htons(local_port)
  };

  if (bind(source_sock, (struct sockaddr*)&address, sizeof(address)) == -1) {
    perror("[ERROR] Unable to bind the listening socket");
    exit(EXIT_FAILURE);
  }

  if (listen(source_sock, 1) == -1) {
    perror("[ERROR] Unable to transition socket to listening state");
    exit(EXIT_FAILURE);
  }

  inet_ntop(AF_INET, &local_ip, friendly_ip, INET_ADDRSTRLEN);
  printf("[INFO] Listening for proxy connection on %s:%d\n", friendly_ip, local_port);

  struct sockaddr_in client_address = {};
  socklen_t client_address_len = sizeof(client_address);

  int accepted_sock = accept(source_sock, (struct sockaddr*)&client_address, &client_address_len);

  if (accepted_sock == -1) {
    perror("[ERROR] Failed to accept incoming connection");
    exit(EXIT_FAILURE);
  }

  // Presume accept gave us a properly formatted address, skip validation
  inet_ntop(AF_INET, &client_address.sin_addr, friendly_ip, INET_ADDRSTRLEN);
  printf("[INFO] Accepted connection from %s:%d\n", friendly_ip, ntohs(client_address.sin_port));

  // Create socket for remote end of the proxy
  int remote_sock = socket(AF_INET, SOCK_STREAM, 0);

  if (remote_sock == -1) {
    perror("[ERROR] Failed to create socket for the remote end of the proxy");
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in remote_address = {
    .sin_addr = remote_ip,
    .sin_family = AF_INET,
    .sin_port = htons(remote_port)
  };

  if (connect(remote_sock, (struct sockaddr*)&remote_address, sizeof(remote_address)) == -1) {
    perror("[ERROR] Unable to established proxied connection to remote");
    exit(EXIT_FAILURE);
  }

  // Similar to the accepted log, ignore validation here as we know it is good from the successful connect
  inet_ntop(AF_INET, &remote_address.sin_addr, friendly_ip, INET_ADDRSTRLEN);
  printf("[INFO] Established remote connection to %s:%d\n", friendly_ip, ntohs(remote_address.sin_port));

  int in_sock = accepted_sock;
  int out_sock = remote_sock;
  char transfer_buff[TRANSFER_BUFFER_SIZE];

  // Communications loop
  while (1) {
    int bytes_in = read(in_sock, transfer_buff, TRANSFER_BUFFER_SIZE);

    if (bytes_in < 0) {
      perror("[ERORR] Failed to read bytes from socket");
      exit(EXIT_FAILURE);
    }

    if (bytes_in == 0) {
      printf("[INFO] Received EOF on socket, ending proxy session\n");
      break;
    }

    int bytes_out = send(out_sock, transfer_buff, bytes_in, 0);

    if (bytes_out == -1) {
      perror("[ERROR] Failed to write bytes to socket");
      exit(EXIT_FAILURE);
    }

    // Swap our sockets to read/write from to handle other end of the stream
    int temp_sock = out_sock;
    out_sock = in_sock;
    in_sock = temp_sock;
  }

  close(accepted_sock);
  close(remote_sock);
  close(source_sock);
  return 0;
}
