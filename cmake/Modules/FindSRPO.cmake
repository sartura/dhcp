if (SRPO_LIBRARIES AND SRPO_INCLUDE_DIRS)
	set(SRPO_FOUND TRUE)
else(SRPO_LIBRARIES AND SRPO_INCLUDE_DIRS)

	find_path(SRPO_INCLUDE_DIR
		NAMES
			srpo_uci.h
			srpo_ubus.h
		PATHS
			/usr/include
			/usr/local/include
			/opt/local/include
			${CMAKE_INCLUDE_PATH}
			${CMAKE_INSTALL_PREFIX}/include
	)

	find_library(SRPO_LIBRARY
		NAMES
			srpo
		PATHS
			/usr/lib
			/usr/lib64
			/usr/local/lib
			/usr/local/lib64
			/opt/local/lib
			${CMAKE_LIBRARY_PATH}
			${CMAKE_INSTALL_PREFIX}/lib
	)

	if (SRPO_INCLUDE_DIR AND SRPO_LIBRARY)
		set(SRPO_FOUND TRUE)
	else (SRPO_INCLUDE_DIR AND SRPO_LIBRARY)
		set(SRPO_FOUND FALSE)
	endif (SRPO_INCLUDE_DIR AND SRPO_LIBRARY)

	set(SRPO_INCLUDE_DIRS ${SRPO_INCLUDE_DIR})
	set(SRPO_LIBRARIES ${SRPO_LIBRARY})
endif(SRPO_LIBRARIES AND SRPO_INCLUDE_DIRS)
