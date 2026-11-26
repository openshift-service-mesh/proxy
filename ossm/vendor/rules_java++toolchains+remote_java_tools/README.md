This Java tools version was built from the bazel repository at commit hash 1ec21d9228a9b0aad0acfbf812f62e13f6addb88
using bazel version 9.2.0.
To build from source the same zip run the commands:

$ git clone https://github.com/bazelbuild/bazel.git
$ git checkout 1ec21d9228a9b0aad0acfbf812f62e13f6addb88
$ bazel build //src:java_tools.zip
