#!/bin/sh

# We support `sudo` and attempt to use it, but fall back to `su`
# otherwise.
if command -v sudo; then
  exec sudo --login -- "$@"
else
  exec su --login root --command "$*"
fi
