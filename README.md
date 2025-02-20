# Delay-Proxy

Delay Proxy is meant to be a lightweight proxy implementation with the ability
to inject arbitrary delays into a TCP-based communications stream. This is meant
as a troubleshooting tool to determine whether or not latency issues are a cause
of application failure.

## Build Requirements

* CMake (3.10+)
* C compiler (C99+)

In order to generate the final executable, you'll need to run the following
command in your checkout:

`cmake . && cmake --build .`

## Runtime Requirements

Supported operating systems include:

* MacOS
* Linux

Proxy configuration defaults to listening on port 8081/tcp and forwarding to
8080/tcp via the loopback address on the local machine. These values can be
changed by providing the `-l` and `-r` arguments for the local and remote IP
addresses, respectively:

`delay-proxy -l <LOCAL IP>[:PORT] -r <REMOTE_IP>[:PORT]`
