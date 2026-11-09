#!/bin/bash

source $(dirname $0)/env.sh

exec "$EM_PYTHON3" $(dirname $0)/link_wrapper.py "$@"
