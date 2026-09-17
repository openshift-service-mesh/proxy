#!/bin/bash

source $(dirname $0)/env.sh

exec "$EM_PYTHON3" $EMSCRIPTEN/emcc.py "$@"
