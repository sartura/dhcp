find_package(PkgConfig)
pkg_check_modules(PC_SR_UCI QUIET sr_uci)

find_path(SR_UCI_INCLUDE_DIR sr_uci.h
	HINTS ${PC_SR_UCI_INCLUDEDIR} ${PC_SR_UCI_INCLUDE_DIRS})

find_library(SR_UCI_LIBRARY NAMES sr_uci libsr_uci
	HINTS ${PC_SR_UCI_LIBDIR} ${PC_SR_UCI_LIBRARY_DIRS})

set(SR_UCI_LIBRARIES ${SR_UCI_LIBRARY})
set(SR_UCI_INCLUDE_DIRS ${SR_UCI_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(SR_UCI DEFAULT_MSG SR_UCI_LIBRARY SR_UCI_INCLUDE_DIR)

mark_as_advanced(SR_UCI_INCLUDE_DIR SR_UCI_LIBRARY)
