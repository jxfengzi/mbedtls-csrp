CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(Srp C)

SET(PROJ_NAME "SRP")

#---------------------------------------------------------------------------------------
# WIN32
#---------------------------------------------------------------------------------------
IF(WIN32)

    MESSAGE(STATUS "build ${PROJ_NAME}for Windows")

    ADD_DEFINITIONS(-D_CRT_SECURE_NO_WARNINGS)
    ADD_DEFINITIONS(-DUNICODE)
    ADD_DEFINITIONS(-D_UNICODE)

ELSE(WIN32)
    
    ADD_DEFINITIONS(-Wno-multichar)

    # release
    #ADD_DEFINITIONS(-O3)

    # debug
    ADD_DEFINITIONS(-g)

    ADD_DEFINITIONS(-fPIC)

    # only position independent executables (PIE) are supported
    ADD_DEFINITIONS(-fPIE)
    ADD_DEFINITIONS(-fpie)

    #-----------------------------------------------------------------------------------
    # APPLE MACOSX
    #-----------------------------------------------------------------------------------
    IF(APPLE)
        MESSAGE(STATUS "build ${PROJ_NAME} for osx")
        ADD_DEFINITIONS(-D__MAC_OSX__)

        # Apple LLVM Compiler
        # SET(CMAKE_CXX_COMPILER /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang++)

        # LLVM gcc Compiler
        SET(CMAKE_CXX_COMPILER /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++)
        SET(CMAKE_CXX_FLAGS -m64)

        #SET(CMAKE_CXX_COMPILER g++)
        #SET(CMAKE_CXX_FLAGS -m64)

    #-----------------------------------------------------------------------------------
    # Linux
    #-----------------------------------------------------------------------------------
    ELSE(APPLE)
        MESSAGE(STATUS "build ${PROJ_NAME} for Linux")
        ADD_DEFINITIONS(-D__LINUX__)
    ENDIF(APPLE)
ENDIF(WIN32)


#---------------------------------------------------------------------------------------
#
# include dir
#
#---------------------------------------------------------------------------------------
INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/../mbedtls-android/mbedtls/include)

#--------------------------------------------------------------------------------------
#
# 3rdpart library dir
#
#--------------------------------------------------------------------------------------
IF (WIN32)
    LINK_DIRECTORIES(${PROJECT_SOURCE_DIR}/../mbedtls-android/android-build/library)
ELSE (WIN32)
    IF(APPLE)
		LINK_DIRECTORIES(/usr/lib/system/)
		LINK_DIRECTORIES("/opt/local/lib")
    ENDIF(APPLE)

    #LINK_DIRECTORIES(${PROJECT_SOURCE_DIR}/../mbedtls-android/android-build/library)
    LINK_DIRECTORIES(${PROJECT_SOURCE_DIR}/../mbedtls-android/build/library)
ENDIF (WIN32)

#--------------------------------------------------------------------------------------
#
# lib
#
#--------------------------------------------------------------------------------------
IF (WIN32)
    SET(OS_LIB)
    SET(MBEDTLS_LIB mbedcrypto.lib mbedtls.lib mbedx509.lib)
ELSE (WIN32)
    SET(OS_LIB)
    SET(MBEDTLS_LIB mbedcrypto mbedtls mbedx509)
ENDIF (WIN32)

MESSAGE(STATUS "os_lib: ${OS_LIB}")
MESSAGE(STATUS "mbedtls_lib: ${MBEDTLS_LIB}")

#-------------------------------------------------------------------------------------
# set output dir
#-------------------------------------------------------------------------------------
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/output)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/output)
MESSAGE(STATUS "executable output:  ${EXECUTABLE_OUTPUT_PATH}")
MESSAGE(STATUS "library output: ${LIBRARY_OUTPUT_PATH}")

#-------------------------------------------------------------------------------------
#
# project
#
#-------------------------------------------------------------------------------------
SET(SRP_SRC srp.c srp.h)
ADD_LIBRARY(srp_shared SHARED ${SRP_SRC})
SET_TARGET_PROPERTIES(srp_shared PROPERTIES OUTPUT_NAME "srp")
SET_TARGET_PROPERTIES(srp_shared PROPERTIES LINKER_LANGUAGE C)
TARGET_LINK_LIBRARIES(srp_shared ${OS_LIB} ${MBEDTLS_LIB})

SET(TEST_SRP_SRC test_srp.c)
ADD_EXECUTABLE(test_srp ${TEST_SRP_SRC})
TARGET_LINK_LIBRARIES(test_srp srp_shared)

SET(TEST_SRP_HAP_SRC test_srp_hap.c)
ADD_EXECUTABLE(test_srp_hap ${TEST_SRP_HAP_SRC})
TARGET_LINK_LIBRARIES(test_srp_hap srp_shared)
