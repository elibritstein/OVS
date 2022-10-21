/*
 * Copyright (c) 2022 NVIDIA Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef INTROSPECT_H
#define INTROSPECT_H

#include <stdbool.h>

#include "openvswitch/compiler.h"

#ifdef HAVE_DL

bool introspect_used_memory(size_t *n_bytes);

#else

static inline bool
introspect_used_memory(size_t *n_bytes OVS_UNUSED)
{
    return false;
}

#endif

#endif /* INTROSPECT_H */
