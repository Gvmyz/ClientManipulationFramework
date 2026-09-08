#ifndef CMF_XENOS_INCLUDES_H
#define CMF_XENOS_INCLUDES_H

// Forced into both C and C++ translation units. Keep C sources such as
// BlackBone's LDasm.c free of C++ standard library declarations.
#ifdef __cplusplus
#include <memory>
#include <iterator>
#endif

#endif
