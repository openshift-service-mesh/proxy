This Java tools version was built from the bazel repository at commit hash 61972bfd7fb6f587fc4576b5114e20758b501806
using bazel version 9.0.0 on platform linux.
To build from source the same zip run the commands:

$ git clone https://github.com/bazelbuild/bazel.git
$ git checkout 61972bfd7fb6f587fc4576b5114e20758b501806
$ bazel build //src:java_tools_prebuilt.zip
