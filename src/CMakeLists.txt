# 自动添加源文件
AUX_SOURCE_DIRECTORY (. SRC_FILES)

ADD_EXECUTABLE (tinyfox ${SRC_FILES})

# 动态链接库
TARGET_LINK_LIBRARIES (tinyfox libcrypto.so libpcap.so)

INSTALL (TARGETS tinyfox DESTINATION /opt/tinyfox)
