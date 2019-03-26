#pragma once

#include <QtCore/qglobal.h>

#ifndef BUILD_STATIC
# if defined(LIBWGIM_LIB)
#  define LIBWGIM_EXPORT Q_DECL_EXPORT
# else
#  define LIBWGIM_EXPORT Q_DECL_IMPORT
# endif
#else
# define LIBWGIM_EXPORT
#endif
