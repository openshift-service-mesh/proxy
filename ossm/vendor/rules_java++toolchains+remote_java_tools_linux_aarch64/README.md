This Java tools version was built from the bazel repository at commit hash 0a9cb2dedba5174df1b03fa74e6fac887aefa0d8
using bazel version 8.4.2 on platform linux_aarch64.
To build from source the same zip run the commands:

$ git clone https://github.com/bazelbuild/bazel.git
$ git checkout 0a9cb2dedba5174df1b03fa74e6fac887aefa0d8
$ bazel build //src:java_tools_prebuilt.zip
