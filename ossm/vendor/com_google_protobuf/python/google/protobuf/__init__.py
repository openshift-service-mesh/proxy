# Protocol Buffers - Google's data interchange format
# Copyright 2008 Google Inc.  All rights reserved.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

# Copyright 2007 Google Inc. All Rights Reserved.

__version__ = '5.26.1'


if __name__ != '__main__':
    try:
        __import__('pkg_resources').declare_namespace(__name__)
    except ImportError:
        __path__ = __import__('pkgutil').extend_path(__path__, __name__)
