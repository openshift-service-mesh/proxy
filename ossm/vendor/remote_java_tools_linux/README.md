This Java tools version was built from the bazel repository at commit hash d63ed9dc3aa715549b436e3743e490d7c9a6dcf5
using bazel version 6.3.2 on platform linux.
To build from source the same zip run the commands:

$ git clone https://github.com/bazelbuild/bazel.git
$ git checkout d63ed9dc3aa715549b436e3743e490d7c9a6dcf5
$ bazel build //src:java_tools_prebuilt.zip
