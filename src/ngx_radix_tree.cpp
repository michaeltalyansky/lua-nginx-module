
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

#include <unistd.h>

#include <string>

#ifdef __cplusplus
extern "C" {
#endif

#include "ngx_http_lua_common.h"
#include "lngx_radix_tree.h"

static int ngx_lua_radix_create(lua_State *L);
static int ngx_lua_radix_addrecord(lua_State *L);
static int ngx_lua_radix_findaddr(lua_State *L);

void
ngx_http_lua_inject_radix_api(ngx_log_t *log, lua_State *L)
{
    lua_pushcfunction(L, ngx_lua_radix_create);
    lua_setfield(L, -2, "radix_create");
    lua_pushcfunction(L, ngx_lua_radix_addrecord);
    lua_setfield(L, -2, "radix_addrecord");
    lua_pushcfunction(L, ngx_lua_radix_findaddr);
    lua_setfield(L, -2, "radix_findaddr");
}

static int ngx_lua_radix_create(lua_State *L)
{
    void *ud;
    lua_Alloc a = lua_getallocf(L, &ud);
    lngx_radix_tree_t *p = lngx_radix_tree_create(a, ud, -1);
    if (NULL == p) {
	return luaL_error(L, "ngx.radix_create: failed to create radix_tree");
    }

    lua_pushlightuserdata (L, p);
    return 1;
}

static int ngx_lua_radix_addrecord(lua_State *L)
{
    std::string addr_str;
    int subnet;
    lngx_radix_tree_t *p;
    unsigned int value;

    int n = lua_gettop(L);
    if (n != 4)
	return luaL_error(L, "ngx.radix_addrecord: wrong number of parameters %d", n);

    if (!lua_islightuserdata(L, 1))
	 return luaL_error(L, "ngx.radix_addrecord: wrong type of parameter 1");
    p = (lngx_radix_tree_t *)lua_touserdata(L, 1);

    if (!lua_isstring(L, 2))
	return luaL_error(L, "ngx.radix_addrecord: wrong type of parameter 2");

    addr_str.assign(lua_tostring (L, 2));

    if (!lua_isnumber(L, 3))
	return luaL_error(L, "ngx.radix_addrecord: wrong type of parameter 3");

    subnet = lua_tonumber (L, 3);

    if (!lua_isnumber(L, 4))
	return luaL_error(L, "ngx.radix_addrecord: wrong type of parameter 4");

    value = lua_tonumber (L, 4);

    // try v4
    struct in_addr addr, mask;
    int rc = inet_pton(AF_INET, addr_str.c_str(), &addr);
    if (1 == rc) {
	if (subnet < 0 || subnet > 32)
	    return luaL_error(L, "ngx.radix_addrecord: bad v4 subnet %d", subnet);
	unsigned int ui = subnet ? ~((1 << (32-subnet)) - 1) : 0;
	*((unsigned int *)&mask) = ui;
	rc = lngx_radix32tree_insert(p, ntohl(addr.s_addr), mask.s_addr, (uintptr_t)value);
	if (NGX_BUSY == rc) {
	    //uintptr_t old = lngx_radix32tree_find(p, ntohl(addr.s_addr));
	    lngx_radix32tree_delete(p, ntohl(addr.s_addr), mask.s_addr);
	    // TODO: could fold old value with the new, for flags and such
	    rc = lngx_radix32tree_insert(p, ntohl(addr.s_addr), mask.s_addr, (uintptr_t)value);
	}
    }
    else
	return luaL_error(L, "ngx.radix_addrecord: bad v4 address/mask (%s)/%d", addr_str.c_str(), subnet);

    lua_pushnumber(L, rc);
    return 1;
}

static int ngx_lua_radix_findaddr(lua_State *L)
{
    lngx_radix_tree_t *p;
    int rc;

    int n = lua_gettop(L);
    if (n != 2)
	return luaL_error(L, "ngx.radix_findaddr: wrong number of parameters %d", n);

    if (!lua_islightuserdata(L, 1))
	 return luaL_error(L, "ngx.radix_findaddr: wrong type of parameter 1");
    p = (lngx_radix_tree_t *)lua_touserdata(L, 1);

    if (lua_isstring(L, 2)) { // string format
        std::string addr_str(lua_tostring (L, 2));

        // v4
        struct in_addr addr;
        rc = inet_pton(AF_INET, addr_str.c_str(), &addr);
        if (1 == rc) {
	    rc = lngx_radix32tree_find(p, ntohl(addr.s_addr));
        }
        else
	    return luaL_error(L, "ngx.radix_findaddr: bad v4 address (%s)", addr_str.c_str());
    }
    else if (lua_isnumber(L, 2)) { // binary address
        unsigned int addr = lua_tonumber (L, 2);
	rc = lngx_radix32tree_find(p, ntohl(addr));
    }
    else
	return luaL_error(L, "ngx.radix_findaddr: wrong type of parameter 2");

    lua_pushnumber(L, rc);
    return 1;
}

static lngx_radix_node_t *lngx_radix_alloc(lngx_radix_tree_t *tree);

static int lngx_pagesize = 0;

lngx_radix_tree_t *
lngx_radix_tree_create(lua_Alloc a, void *ud, lngx_int_t preallocate)
{
    uint32_t           key, mask, inc;
    lngx_radix_tree_t  *tree;

    if (!lngx_pagesize)
	lngx_pagesize = getpagesize();

    tree = (lngx_radix_tree_t *)lngx_palloc(a, ud, sizeof(lngx_radix_tree_t));
    if (tree == NULL) {
        return NULL;
    }

    tree->a = a;
    tree->ud = ud;
    tree->free = NULL;
    tree->start = NULL;
    tree->size = 0;

    tree->root = lngx_radix_alloc(tree);
    if (tree->root == NULL) {
        return NULL;
    }

    tree->root->right = NULL;
    tree->root->left = NULL;
    tree->root->parent = NULL;
    tree->root->value = NGX_RADIX_NO_VALUE;

    if (preallocate == 0) {
        return tree;
    }

    /*
     * Preallocation of first nodes : 0, 1, 00, 01, 10, 11, 000, 001, etc.
     * increases TLB hits even if for first lookup iterations.
     * On 32-bit platforms the 7 preallocated bits takes continuous 4K,
     * 8 - 8K, 9 - 16K, etc.  On 64-bit platforms the 6 preallocated bits
     * takes continuous 4K, 7 - 8K, 8 - 16K, etc.  There is no sense to
     * to preallocate more than one page, because further preallocation
     * distributes the only bit per page.  Instead, a random insertion
     * may distribute several bits per page.
     *
     * Thus, by default we preallocate maximum
     *     6 bits on amd64 (64-bit platform and 4K pages)
     *     7 bits on i386 (32-bit platform and 4K pages)
     *     7 bits on sparc64 in 64-bit mode (8K pages)
     *     8 bits on sparc64 in 32-bit mode (8K pages)
     */

    if (preallocate == -1) {
        switch (lngx_pagesize / sizeof(lngx_radix_node_t)) {

        /* amd64 */
        case 128:
            preallocate = 6;
            break;

        /* i386, sparc64 */
        case 256:
            preallocate = 7;
            break;

        /* sparc64 in 32-bit mode */
        default:
            preallocate = 8;
        }
    }

    mask = 0;
    inc = 0x80000000;

    while (preallocate--) {

        key = 0;
        mask >>= 1;
        mask |= 0x80000000;

        do {
            if (lngx_radix32tree_insert(tree, key, mask, NGX_RADIX_NO_VALUE)
                != NGX_OK)
            {
                return NULL;
            }

            key += inc;

        } while (key);

        inc >>= 1;
    }

    return tree;
}


lngx_int_t
lngx_radix32tree_insert(lngx_radix_tree_t *tree, uint32_t key, uint32_t mask,
    uintptr_t value)
{
    uint32_t           bit;
    lngx_radix_node_t  *node, *next;

    bit = 0x80000000;

    node = tree->root;
    next = tree->root;

    while (bit & mask) {
        if (key & bit) {
            next = node->right;

        } else {
            next = node->left;
        }

        if (next == NULL) {
            break;
        }

        bit >>= 1;
        node = next;
    }

    if (next) {
        if (node->value != NGX_RADIX_NO_VALUE) {
            return NGX_BUSY;
        }

        node->value = value;
        return NGX_OK;
    }

    while (bit & mask) {
        next = lngx_radix_alloc(tree);
        if (next == NULL) {
            return NGX_ERROR;
        }

        next->right = NULL;
        next->left = NULL;
        next->parent = node;
        next->value = NGX_RADIX_NO_VALUE;

        if (key & bit) {
            node->right = next;

        } else {
            node->left = next;
        }

        bit >>= 1;
        node = next;
    }

    node->value = value;

    return NGX_OK;
}


lngx_int_t
lngx_radix32tree_delete(lngx_radix_tree_t *tree, uint32_t key, uint32_t mask)
{
    uint32_t           bit;
    lngx_radix_node_t  *node;

    bit = 0x80000000;
    node = tree->root;

    while (node && (bit & mask)) {
        if (key & bit) {
            node = node->right;

        } else {
            node = node->left;
        }

        bit >>= 1;
    }

    if (node == NULL) {
        return NGX_ERROR;
    }

    if (node->right || node->left) {
        if (node->value != NGX_RADIX_NO_VALUE) {
            node->value = NGX_RADIX_NO_VALUE;
            return NGX_OK;
        }

        return NGX_ERROR;
    }

    for ( ;; ) {
        if (node->parent->right == node) {
            node->parent->right = NULL;

        } else {
            node->parent->left = NULL;
        }

        node->right = tree->free;
        tree->free = node;

        node = node->parent;

        if (node->right || node->left) {
            break;
        }

        if (node->value != NGX_RADIX_NO_VALUE) {
            break;
        }

        if (node->parent == NULL) {
            break;
        }
    }

    return NGX_OK;
}


uintptr_t
lngx_radix32tree_find(lngx_radix_tree_t *tree, uint32_t key)
{
    uint32_t           bit;
    uintptr_t          value;
    lngx_radix_node_t  *node;

    bit = 0x80000000;
    value = NGX_RADIX_NO_VALUE;
    node = tree->root;

    while (node) {
        if (node->value != NGX_RADIX_NO_VALUE) {
            value = node->value;
        }

        if (key & bit) {
            node = node->right;

        } else {
            node = node->left;
        }

        bit >>= 1;
    }

    return value;
}


#if (NGX_HAVE_INET6)

lngx_int_t
lngx_radix128tree_insert(lngx_radix_tree_t *tree, u_char *key, u_char *mask,
    uintptr_t value)
{
    u_char             bit;
    lngx_uint_t         i;
    lngx_radix_node_t  *node, *next;

    i = 0;
    bit = 0x80;

    node = tree->root;
    next = tree->root;

    while (bit & mask[i]) {
        if (key[i] & bit) {
            next = node->right;

        } else {
            next = node->left;
        }

        if (next == NULL) {
            break;
        }

        bit >>= 1;
        node = next;

        if (bit == 0) {
            if (++i == 16) {
                break;
            }

            bit = 0x80;
        }
    }

    if (next) {
        if (node->value != NGX_RADIX_NO_VALUE) {
            return NGX_BUSY;
        }

        node->value = value;
        return NGX_OK;
    }

    while (bit & mask[i]) {
        next = lngx_radix_alloc(tree);
        if (next == NULL) {
            return NGX_ERROR;
        }

        next->right = NULL;
        next->left = NULL;
        next->parent = node;
        next->value = NGX_RADIX_NO_VALUE;

        if (key[i] & bit) {
            node->right = next;

        } else {
            node->left = next;
        }

        bit >>= 1;
        node = next;

        if (bit == 0) {
            if (++i == 16) {
                break;
            }

            bit = 0x80;
        }
    }

    node->value = value;

    return NGX_OK;
}


lngx_int_t
lngx_radix128tree_delete(lngx_radix_tree_t *tree, u_char *key, u_char *mask)
{
    u_char             bit;
    lngx_uint_t         i;
    lngx_radix_node_t  *node;

    i = 0;
    bit = 0x80;
    node = tree->root;

    while (node && (bit & mask[i])) {
        if (key[i] & bit) {
            node = node->right;

        } else {
            node = node->left;
        }

        bit >>= 1;

        if (bit == 0) {
            if (++i == 16) {
                break;
            }

            bit = 0x80;
        }
    }

    if (node == NULL) {
        return NGX_ERROR;
    }

    if (node->right || node->left) {
        if (node->value != NGX_RADIX_NO_VALUE) {
            node->value = NGX_RADIX_NO_VALUE;
            return NGX_OK;
        }

        return NGX_ERROR;
    }

    for ( ;; ) {
        if (node->parent->right == node) {
            node->parent->right = NULL;

        } else {
            node->parent->left = NULL;
        }

        node->right = tree->free;
        tree->free = node;

        node = node->parent;

        if (node->right || node->left) {
            break;
        }

        if (node->value != NGX_RADIX_NO_VALUE) {
            break;
        }

        if (node->parent == NULL) {
            break;
        }
    }

    return NGX_OK;
}


uintptr_t
lngx_radix128tree_find(lngx_radix_tree_t *tree, u_char *key)
{
    u_char             bit;
    uintptr_t          value;
    lngx_uint_t         i;
    lngx_radix_node_t  *node;

    i = 0;
    bit = 0x80;
    value = NGX_RADIX_NO_VALUE;
    node = tree->root;

    while (node) {
        if (node->value != NGX_RADIX_NO_VALUE) {
            value = node->value;
        }

        if (key[i] & bit) {
            node = node->right;

        } else {
            node = node->left;
        }

        bit >>= 1;

        if (bit == 0) {
            i++;
            bit = 0x80;
        }
    }

    return value;
}

#endif


static lngx_radix_node_t *
lngx_radix_alloc(lngx_radix_tree_t *tree)
{
    lngx_radix_node_t  *p;

    if (tree->free) {
        p = tree->free;
        tree->free = tree->free->right;
        return p;
    }

    if (tree->size < sizeof(lngx_radix_node_t)) {
        tree->start = (char *)lngx_pmemalign(tree->a, tree->ud, lngx_pagesize, lngx_pagesize);
        if (tree->start == NULL) {
            return NULL;
        }

        tree->size = lngx_pagesize;
    }

    p = (lngx_radix_node_t *) tree->start;
    tree->start += sizeof(lngx_radix_node_t);
    tree->size -= sizeof(lngx_radix_node_t);

    return p;
}

#ifdef __cplusplus
}
#endif

