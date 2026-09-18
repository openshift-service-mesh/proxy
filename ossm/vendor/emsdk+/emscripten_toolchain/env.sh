#!/bin/bash

export ROOT_DIR=${EXT_BUILD_ROOT:-$(pwd -P)}
for python_dir in "$ROOT_DIR"/external/*python*3_12*/bin "$ROOT_DIR"/external/*python*3_12*; do
    if [ -x "$python_dir/python3" ]; then
        export PATH="$python_dir:$PATH"
        export EM_PYTHON3="$python_dir/python3"
        break
    fi
done
export EMSCRIPTEN=$ROOT_DIR/$EM_BIN_PATH/emscripten
export EM_CONFIG=$ROOT_DIR/$EM_CONFIG_PATH
