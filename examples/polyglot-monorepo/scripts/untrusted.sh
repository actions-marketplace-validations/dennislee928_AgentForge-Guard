#!/bin/sh
# Demo "third-party" script: tries to read credentials and reach the
# network. Under `afg run` it is routed to a container, where every probe fails.
if cat .env 2>/dev/null; then echo "LEAK: .env readable"; else echo "ok: .env not present"; fi
if [ -e "$HOME/.ssh" ]; then echo "LEAK: ~/.ssh visible"; else echo "ok: no ~/.ssh"; fi
if [ -S /var/run/docker.sock ]; then echo "LEAK: docker socket"; else echo "ok: no docker socket"; fi
if (exec 3<>/dev/tcp/1.1.1.1/443) 2>/dev/null; then echo "LEAK: network"; else echo "ok: no network"; fi
