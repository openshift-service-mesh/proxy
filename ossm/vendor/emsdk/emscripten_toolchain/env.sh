#!/bin/bash

export ROOT_DIR=${EXT_BUILD_ROOT:-$(pwd -P)}
export EMSCRIPTEN=$ROOT_DIR/$EM_BIN_PATH/emscripten
export EM_CONFIG=$ROOT_DIR/$EM_CONFIG_PATH

# Add Python to PATH for remote execution environments
# Find Python from rules_python toolchain (supports multiple platform names)
for python_dir in "$ROOT_DIR"/external/python3_*; do
    if [ -x "$python_dir/bin/python3" ]; then
        export PATH="$python_dir/bin:$PATH"
        break
    fi
done
