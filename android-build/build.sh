#!/bin/sh

cmake -DCMAKE_TOOLCHAIN_FILE=$PWD/../android-cmake/android.toolchain.cmake      \
      -DANDROID_NDK=$ANDROID_NDK                                                \
      -DCMAKE_BUILD_TYPE=Release                                                \
      -DANDROID_ABI="armeabi-v7a with NEON"                                     \
      ../

cmake --build .
