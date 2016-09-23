
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _LNGX_RADIX_TREE_H_INCLUDED_
#define _LNGX_RADIX_TREE_H_INCLUDED_


#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#define NGX_HAVE_INET6 1

typedef int lngx_int_t;
typedef unsigned int lngx_uint_t;

#define NGX_RADIX_NO_VALUE   (uintptr_t) -1

#ifdef __cplusplus
extern "C" {
#endif

void ngx_http_lua_inject_radix_api(ngx_log_t *log, lua_State *L);

typedef struct lngx_radix_node_s  lngx_radix_node_t;

static inline void *lngx_pmemalign(lua_Alloc a, void *ud, int size, int ALIGN) {
    void *mem = a(ud, NULL, 0, size+ALIGN+sizeof(void*));
    void **ptr = (void**)((uintptr_t)((char *)mem+ALIGN+sizeof(void*)) & ~(ALIGN-1));
    ptr[-1] = mem;
    return ptr;
}

static inline void *lngx_palloc(lua_Alloc a, void *ud, size_t size)
{
    return a(ud, NULL, 0, size);
}

struct lngx_radix_node_s {
    lngx_radix_node_t  *right;
    lngx_radix_node_t  *left;
    lngx_radix_node_t  *parent;
    uintptr_t          value;
};

typedef struct {
    lngx_radix_node_t  *root;
    lua_Alloc        a;
    void *ud;
    lngx_radix_node_t  *free;
    char              *start;
    size_t             size;
} lngx_radix_tree_t;


lngx_radix_tree_t *lngx_radix_tree_create(lua_Alloc a, void *ud, 
    lngx_int_t preallocate);

lngx_int_t lngx_radix32tree_insert(lngx_radix_tree_t *tree,
    uint32_t key, uint32_t mask, uintptr_t value);
lngx_int_t lngx_radix32tree_delete(lngx_radix_tree_t *tree,
    uint32_t key, uint32_t mask);
uintptr_t lngx_radix32tree_find(lngx_radix_tree_t *tree, uint32_t key);

#if (NGX_HAVE_INET6)
lngx_int_t lngx_radix128tree_insert(lngx_radix_tree_t *tree,
    u_char *key, u_char *mask, uintptr_t value);
lngx_int_t lngx_radix128tree_delete(lngx_radix_tree_t *tree,
    u_char *key, u_char *mask);
uintptr_t lngx_radix128tree_find(lngx_radix_tree_t *tree, u_char *key);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _LNGX_RADIX_TREE_H_INCLUDED_ */
