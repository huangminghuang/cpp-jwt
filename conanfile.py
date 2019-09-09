#!/usr/bin/env python
# -*- coding: utf-8 -*-

from conans import ConanFile, CMake, tools
import os


class CppJwtConan(ConanFile):
    name = "cpp-jwt"
    version = "1.2.1"
    url = "https://github.com/huangminghuang/conan-cpp-jwt"
    description = "A C++ library for handling JWT tokens"
    license = "https://github.com/arun11299/cpp-jwt/blob/master/LICENSE"
    no_copy_source = True
    exports_sources = "include/*", "LICENSE"
    requires = "OpenSSL/latest_1.1.1x@conan/stable", "jsonformoderncpp/3.7.0@vthiery/stable"  

    def package_id(self):
        self.info.header_only()

    def package(self):
        self.copy(pattern="LICENSE")
        self.copy(pattern="*.[i|h]pp", dst="include", src="include", excludes='jwt/json*',  keep_path=True)