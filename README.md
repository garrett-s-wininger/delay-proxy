# Delay-Proxy

Delay Proxy is meant to be a light-weight forward proxy implementation with the
ability to inject arbitrary delays into a TCP-based communications stream. This
is meant as a troubleshooting tool to determine whether or not latency issues
are a cause of application failure.

## Build Requirements

* CMake (3.10+)
* C compiler

In order to generate the final executable, you'll need to run the following
command in your checkout:

`cmake --build .`

## Runtime Requirements

* Linux-based OS Distribution

Proxy configuration is _currently_ hardcoded to listening on port 8081/tcp and
forwarding to 8080/tcp which will be addressed in the future. We also default
to only operating on the loopback address of the machine, though this can be
changed by providing the `-l` and `-r` arguments for the local and remote IP
addresses, respectively:

`delay-proxy -l <LOCAL IP> -r <REMOTE_IP>`
