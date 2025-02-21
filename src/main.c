#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define LOG_LEVEL_ERROR "ERROR"
#define LOG_LEVEL_INFO "INFO"
#define LOOPBACK "127.0.0.1"
#define MAX_LOG_HEADER_SIZE 10
#define MAX_LOG_SIZE 255
#define MILIS_TO_NANOS_MULTIPLIER 1000000
#define TRANSFER_BUFFER_SIZE 1024

/**
 * Contains the arguments required for proper functioning of the application
 * which are used to configure listening addresses and ports for the proxy.
 */
struct program_args {
  /** Duration to delay socket operations for. */
  struct timespec delay_duration;
  /** IP on the locl machine which the proxy listens. */
  struct in_addr local_ip;
  /** Port on the local machine which the proxy listens. */
  uint16_t local_port;
  /** Remote IP which data is proxied to. */
  struct in_addr remote_ip;
  /** Remote port which data is proxied to. */
  uint16_t remote_port;
};

/**
 * Specifies a file descriptor to read and write from for operations against
 * pairs of sockets.
 */
struct rw_socket_pair {
  /** User friendly identifier to indicate which pair is in operation. */
  const char* identifier;
  /** Amount of delay to introduce into the read/write op. */
  struct timespec delay_duration;
  /** Socket FD to read from. */
  int read_fd;
  /** Socket FD to wrtie to. */
  int write_fd;
};

/**
 * Prints text to the terminal to indicate which operations are available to
 * consumers of the software.
 */
void print_usage(void) {
  printf("Inject delays in network communications between two TCP endpoints\n\n");
  printf("Usage:\n");
  printf(" %-20s - Print this usage information\n", "delay-proxy -h");
  printf(" %-20s - Run the proxy with default settings\n", "delay-proxy");
  printf(" %-20s - Run the proxy with the provided setings\n\n", "delay-proxy OPTIONS");
  printf("Options:\n");
  printf(" %-20s - Duration to delay socket operations, specified in ms\n", "-d DURATION");
  printf(" %-20s - Listen on the specified IPv4 address/port\n", "-l ADDRESS[:PORT]");
  printf(" %-20s - Remote IPv4 address/port to proxy connection data to\n", "-r ADDRESS[:PORT]");
}

/**
 * Logs messages to STDERR in the format of "[LEVEL] TEXT\n".
 *
 * @param log_level level that the log message represents
 * @param format format string of the log message body
 * @param ... placeholder values for the specified format
 */
void log_message(const char* log_level, const char* format, ...) {
  // Initial format of our header, this is our destination buffer so we need MAX_LOG_SIZE
  char message[MAX_LOG_SIZE] = { 0 };
  const int header_chars = snprintf(message, MAX_LOG_HEADER_SIZE, "[%s] ", log_level);

  // Using variadic args, populate our provided format, up to MAX_LOG_SIZE
  char message_text[MAX_LOG_SIZE] = { 0 };
  va_list extra_args;
  va_start(extra_args, format);
  const int message_chars = vsnprintf(message_text, MAX_LOG_SIZE, format, extra_args);
  va_end(extra_args);

  // Identify how much space we have left, including the null terminator and newline
  const int remaining_space = MAX_LOG_SIZE - header_chars - message_chars - 2;

  // Error out if we're going to overflow
  if (remaining_space < 0) {
    fprintf(stderr, "[ERROR] Not enough buffer space for requested formatting\n");
    exit(EXIT_FAILURE);
  }

  // Concat the header, message, and newline
  strncat(message, message_text, remaining_space);
  strncat(message, "\n", 1);

  // Output the log
  fputs(message, stderr);
}

/**
 * Given an input string, parses out the IP address and port number,
 * if provided and separated by a colon.
 *
 * On success, sets the provided address and port pointers to their parsed
 * values. Port is only set if one is specified. Exits the program on invalid
 * values as this operation needs to succeed in order to do any further proxy
 * operations.
 *
 * @param input pointer to string for parsing in the format of ADDRESS[:PORT]
 * @param address pointer to the address struct which will be set on success
 * @param port pointer to the port data which will be set on a success
 */
void parse_ip_port_combo(const char* input, struct in_addr* address, uint16_t* port) {
  // Copy the input to a mutable buffer to share implementation between the
  // port and no-port address formats
  size_t input_len = strlen(input);
  char* address_str = strndup(input, input_len + 1);

  // Start of port separator, if found
  const char* result = NULL;

  // We've found a port separator, parse it as appropriate
  if ((result = strchr(address_str, ':')) != NULL) {
    result += sizeof(char);
    size_t result_len = strlen(result);

    // Validate all values are numeric in the port portion of the input string
    // to avoid a successful `atoi` parse that doesn't properly account for
    // malformed data
    for (int i = 0; i < result_len; ++i) {
      if (!isdigit(result[i])) {
        log_message(LOG_LEVEL_ERROR, "Port %s is unparseable", result);
        exit(EXIT_FAILURE);
      }
    }

    int parsed_port = atoi(result);

    // Ensure we're not using the placeholder or an invalid port value
    if (parsed_port == 0 || parsed_port > UINT16_MAX) {
      log_message(LOG_LEVEL_ERROR, "Port %s is out of range, needed 1-65535", result);
      exit(EXIT_FAILURE);
    }

    // Update the given port number
    *port = (uint16_t)parsed_port;

    // Update the colon to a null termination in order to limit how far the
    // IP parsing proceeds
    ptrdiff_t chars_to_separator = result - 1 - address_str;
    address_str[chars_to_separator] = '\0';
  }

  // Parse the IP address
  if (inet_pton(AF_INET, address_str, address) == 0) {
    log_message(LOG_LEVEL_ERROR, "IP %s is not a valid IPv4 address", optarg);
    exit(EXIT_FAILURE);
  }

  // Free our duplicated string used during the parse attempt
  free(address_str);
}

/**
 * Parses single-character options from the command line in order to determine
 * the proper IP/port configurations.
 *
 * Updates `arg_ptr` with the contents of the passed arguments on success.
 * Exits gracefully when `-h` is provided to print this usage
 * or fails the program when an invalid argument is encountered.
 *
 * @param argc standard C main function arg for count of arguments
 * @param argv standard C main function argument vector
 * @param arg_ptr destination to copy parsed arguments to
 */
void process_cmdline(int argc, char** argv, struct program_args* arg_ptr) {
  // Storage for parsed arguments
  struct program_args parsed_args = {
    .delay_duration = { 0 },
    .local_ip = { 0 },
    .local_port = 8081,
    .remote_ip = { 0 },
    .remote_port = 8080
  };

  // Default local/remote IPs, don't bother with validation
  inet_pton(AF_INET, LOOPBACK, &parsed_args.local_ip);
  inet_pton(AF_INET, LOOPBACK, &parsed_args.remote_ip);

  // Loop variable storage
  int opt;
  size_t arg_len;

  // Parsing loop
  while ((opt = getopt(argc, argv, "hd:l:r:")) != -1) {
    switch (opt) {
      case 'h':
        print_usage();
        exit(EXIT_SUCCESS);
      case 'd':
        arg_len = strlen(optarg);

        // Ensure we have all numeric values to avoid truncation issues
        for (int i = 0; i < arg_len; ++i) {
          if (!isdigit(optarg[i])) {
            log_message(
              LOG_LEVEL_ERROR,
              "Received delay value of %s which is non-numeric",
              optarg
            );

            exit(EXIT_FAILURE);
          }
        }

        // Set our returned delay to be the provided number * milliseconds
        long delay = atol(optarg);

        // Keep us under a second to only fill a single portion of the associated struct
        if (delay >= 1000) {
          log_message(
            LOG_LEVEL_ERROR,
            "Delay must be below a second, received %ld miliseconds",
            delay
          );

          exit(EXIT_FAILURE);
        }

        // Update our return value to have the provided delay
        struct timespec delay_spec = {
          .tv_sec = 0,
          .tv_nsec = delay * MILIS_TO_NANOS_MULTIPLIER
        };

        parsed_args.delay_duration = delay_spec;
        break;
      case 'l':
        parse_ip_port_combo(optarg, &parsed_args.local_ip, &parsed_args.local_port);
        break;
      case 'r':
        parse_ip_port_combo(optarg, &parsed_args.remote_ip, &parsed_args.remote_port);
        break;
      default:
        printf("\n");
        print_usage();
        exit(EXIT_FAILURE);
    }
  }

  memcpy(arg_ptr, &parsed_args, sizeof(parsed_args));
}

/**
 * Defines the data flow from one socket to another without handling
 * transmission in the opposite direction.
 *
 * On success, returns NULL to be compatible with the `pthread` API. Exits the
 * application on a read/write failure.
 *
 * @param socket_config a pair of sockets, one to read from and one to write to
 * @returns NULL
 */
void* simplex_connection(void* socket_config) {
  struct rw_socket_pair* config = (struct rw_socket_pair*)socket_config;
  char transfer_buff[TRANSFER_BUFFER_SIZE];

  // Communications loop
  while (1) {
    int bytes_in = recv(config->read_fd, transfer_buff, TRANSFER_BUFFER_SIZE, 0);

    if (bytes_in == -1) {
      if (errno == ECONNRESET) {
        log_message(
          LOG_LEVEL_INFO,
          "Read target reset (%s), ending affected half of proxy connection",
          config->identifier
        );

        break;
      } else {
        perror("[ERROR] Failed to read bytes from socket");
        exit(EXIT_FAILURE);
      }
    }

    if (bytes_in == 0) {
      log_message(
        LOG_LEVEL_INFO,
        "Received EOF on simplex read (%s), ending affected half of proxy connection\n",
        config->identifier
      );

      break;
    }

    // Only inject waits if we have requested it
    if (config->delay_duration.tv_sec != 0 || config->delay_duration.tv_nsec != 0) {
      struct timespec delay_remainder = { 0 };
      struct timespec* delay_target = &config->delay_duration;
      int sleep_result = 0;

      // Continue re-sleeping until we have handled our entire value
      do {
        sleep_result = nanosleep(delay_target, &delay_remainder);

        if (sleep_result == -1) {
          // EINTR means a remainder to sleep for, otherwise an actual error occurred
          if (errno == EINTR) {
            delay_target = &delay_remainder;
          } else {
            perror("[ERROR] Unable to inject specified delay");
            exit(EXIT_FAILURE);
          }
        }
      } while (sleep_result != 0);
    }

    if (send(config->write_fd, transfer_buff, bytes_in, 0) == -1) {
      if (errno == EPIPE) {
        log_message(
          LOG_LEVEL_INFO,
          "Write target (%s) closed, ending affected half of proxy connection",
          config->identifier
        );

        break;
      } else {
        perror("[ERROR] Failed to write bytes to socket");
        exit(EXIT_FAILURE);
      }
    }
  }

  return NULL;
}

int main(int argc, char** argv) {
  // Argument parsing
  struct program_args args = { 0 };
  process_cmdline(argc, argv, &args);

  // Log running process
  log_message(LOG_LEVEL_INFO, "Running as PID %d", getpid());

  if (args.delay_duration.tv_sec != 0 || args.delay_duration.tv_nsec != 0) {
    log_message(
      LOG_LEVEL_INFO,
      "Running with %ld ms delay between read/write",
      args.delay_duration.tv_nsec / MILIS_TO_NANOS_MULTIPLIER
    );
  }

  // Create base of local listening socket
  int source_sock = socket(AF_INET, SOCK_STREAM, 0);

  if (source_sock == -1) {
    perror("[ERROR] Unable to create socket for incoming connection");
    exit(EXIT_FAILURE);
  }

  // Set socket operations for proper address/port reuse
  int sock_opt = 1;

  if (setsockopt(source_sock, SOL_SOCKET, SO_REUSEPORT, &sock_opt, sizeof(sock_opt)) == -1) {
    perror("[ERROR] Unable to set port reuse for the incoming socket");
    exit(EXIT_FAILURE);
  }

  if (setsockopt(source_sock, SOL_SOCKET, SO_REUSEADDR, &sock_opt, sizeof(sock_opt)) == -1) {
    perror("[ERROR] Unable to set address reuse for the incoming socket");
    exit(EXIT_FAILURE);
  }

  // Prepare the local side of the proxy
  struct sockaddr_in address = {
    .sin_addr = args.local_ip,
    .sin_family = AF_INET,
    .sin_port = htons(args.local_port)
  };

  if (bind(source_sock, (struct sockaddr*)&address, sizeof(address)) == -1) {
    perror("[ERROR] Unable to bind the listening socket");
    exit(EXIT_FAILURE);
  }

  if (listen(source_sock, 1) == -1) {
    perror("[ERROR] Unable to transition socket to listening state");
    exit(EXIT_FAILURE);
  }

  char friendly_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &args.local_ip, friendly_ip, INET_ADDRSTRLEN);

  log_message(
    LOG_LEVEL_INFO,
    "Listening for proxy connection on %s:%d",
    friendly_ip,
    args.local_port
  );

  // Prepare storage for the client's connection information
  struct sockaddr_in client_address = {};
  socklen_t client_address_len = sizeof(client_address);

  int accepted_sock = accept(source_sock, (struct sockaddr*)&client_address, &client_address_len);

  if (accepted_sock == -1) {
    perror("[ERROR] Failed to accept incoming connection");
    exit(EXIT_FAILURE);
  }

  // Presume accept gave us a properly formatted address, skip validation
  inet_ntop(AF_INET, &client_address.sin_addr, friendly_ip, INET_ADDRSTRLEN);

  log_message(
    LOG_LEVEL_INFO,
    "Accepted connection from %s:%d",
    friendly_ip,
    ntohs(client_address.sin_port)
  );

  // Create socket for remote end of the proxy
  int remote_sock = socket(AF_INET, SOCK_STREAM, 0);

  if (remote_sock == -1) {
    perror("[ERROR] Failed to create socket for the remote end of the proxy");
    exit(EXIT_FAILURE);
  }

  // Configure remote end of the proxy
  struct sockaddr_in remote_address = {
    .sin_addr = args.remote_ip,
    .sin_family = AF_INET,
    .sin_port = htons(args.remote_port)
  };

  if (connect(remote_sock, (struct sockaddr*)&remote_address, sizeof(remote_address)) == -1) {
    perror("[ERROR] Unable to established proxied connection to remote");
    exit(EXIT_FAILURE);
  }

  // Similar to the accepted log, ignore validation here as we know it is good
  // from the successful connect
  inet_ntop(AF_INET, &remote_address.sin_addr, friendly_ip, INET_ADDRSTRLEN);

  log_message(
    LOG_LEVEL_INFO,
    "Established remote connection to %s:%d",
    friendly_ip,
    ntohs(remote_address.sin_port)
  );

  // Define which FDs to read and write for each connection half
  struct rw_socket_pair local_to_remote_pair = {
    .identifier = "local",
    .delay_duration = args.delay_duration,
    .read_fd = accepted_sock,
    .write_fd = remote_sock
  };

  struct rw_socket_pair remote_to_local_pair = {
    .identifier = "remote",
    .delay_duration = args.delay_duration,
    .read_fd = remote_sock,
    .write_fd = accepted_sock
  };

  // Establish threads for each half of the connection
  pthread_t local_to_remote_simplex, remote_to_local_simplex;

  if (pthread_create(
      &local_to_remote_simplex,
      NULL,
      simplex_connection,
      &local_to_remote_pair) != 0) {
    perror("[ERROR] Unable to create local to remote thread");
    exit(EXIT_FAILURE);
  }

  if (pthread_create(
        &remote_to_local_simplex,
        NULL,
        simplex_connection,
        &remote_to_local_pair) != 0) {
    perror("[ERROR] Unable to create local to remote thread");
    exit(EXIT_FAILURE);
  }

  // Wait on each side of the connection to close before we clean up our resources
  const pthread_t join_threads[] = { local_to_remote_simplex, remote_to_local_simplex };

  for (int i = 0; i < sizeof(join_threads) / sizeof(join_threads[0]); ++i) {
    if (pthread_join(join_threads[i], NULL) != 0) {
      perror("[ERROR] Encountered error while waiting on connection thread");
      exit(EXIT_FAILURE);
    }
  }

  // Free resources
  close(accepted_sock);
  close(remote_sock);
  close(source_sock);
  return 0;
}
