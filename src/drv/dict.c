// #include "stdafx.h"

#pragma warning(disable: 4100)
#pragma warning(disable: 4706)
/*
 * Dictionary Abstract Data Type
 * Copyright (C) 1997 Kaz Kylheku <kaz@ashi.footprints.net>
 *
 * Free Software License:
 *
 * All rights are reserved by the author, with the following exceptions:
 * Permission is granted to freely reproduce and distribute this software,
 * possibly in exchange for a fee, provided that this copyright notice appears
 * intact. Permission is also granted to adapt this software to produce
 * derivative works, as long as the modified versions carry this copyright
 * notice and additional notices stating that the work has been modified.
 * This source code may be translated into executable form and incorporated
 * into proprietary software; there is no requirement for such software to
 * contain a copyright notice related to this source.
 *
 * $Id: dict.c,v 1.1.1.1 2001/05/30 12:31:04 work Exp $
 * $Name:  $
 */

#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#define DICT_IMPLEMENTATION
#include "dict.h"

#ifdef KAZLIB_RCSID
static const char rcsid[] = "$Id: dict.c,v 1.1.1.1 2001/05/30 12:31:04 work Exp $";
#endif

/*
 * These macros provide short convenient names for structure members,
 * which are embellished with dict_ prefixes so that they are
 * properly confined to the documented namespace. It's legal for a
 * program which uses dict to define, for instance, a macro called ``parent''.
 * Such a macro would interfere with the dnode_t struct definition.
 * In general, highly portable and reusable C modules which expose their
 * structures need to confine structure member names to well-defined spaces.
 * The resulting identifiers aren't necessarily convenient to use, nor
 * readable, in the implementation, however!
 */

#define left dict_left
#define right dict_right
#define parent dict_parent
#define color dict_color
#define key dict_key
#define data dict_data

#define nilnode dict_nilnode
#define nodecount dict_nodecount
#define maxcount dict_maxcount
#define compare dict_compare
#define allocnode dict_allocnode
#define freenode dict_freenode
#define context dict_context
#define dupes dict_dupes

#define dict_root(D) ((D)->nilnode.left)
#define dict_nil(D) (&(D)->nilnode)

static dnode_t *dnode_alloc(void *context);
static void dnode_free(dnode_t *node, void *context);

/*
 * Perform a ``left rotation'' adjustment on the tree.  The given node P and
 * its right child C are rearranged so that the P instead becomes the left
 * child of C.   The left subtree of C is inherited as the new right subtree
 * for P.  The ordering of the keys within the tree is thus preserved.
 */

static void rotate_left(dict_t *dict, dnode_t *upper)
{
    dnode_t *lower, *lowleft, *upparent;

#ifdef WITH_ASSERT
    assert (upper != dict_nil(dict));
    assert (upper->right != dict_nil(dict));
#endif

    lower = upper->right;
    upper->right = lowleft = lower->left;
    lowleft->parent = upper;

    lower->parent = upparent = upper->parent;

    /* don't need to check for root node here because root->parent is
       the sentinel nil node, and root->parent->left points back to root */

    if (upper == upparent->left) {
        upparent->left = lower;
    } else {
#ifdef WITH_ASSERT
        assert (upper == upparent->right);
#endif
        upparent->right = lower;
    }

    lower->left = upper;
    upper->parent = lower;
}

/*
 * This operation is the ``mirror'' image of rotate_left. It is
 * the same procedure, but with left and right interchanged.
 */

static void rotate_right(dict_t *dict, dnode_t *upper)
{
    dnode_t *lower, *lowright, *upparent;

#ifdef WITH_ASSERT
    assert (upper != dict_nil(dict));
    assert (upper->left != dict_nil(dict));
#endif

    lower = upper->left;
    upper->left = lowright = lower->right;
    lowright->parent = upper;

    lower->parent = upparent = upper->parent;

    if (upper == upparent->right) {
        upparent->right = lower;
    } else {
#ifdef WITH_ASSERT
        assert (upper == upparent->left);
#endif
        upparent->left = lower;
    }

    lower->right = upper;
    upper->parent = lower;
}

/*
 * This procedure performs a verification that the given subtree is a binary
 * search tree. It performs an inorder traversal of the tree using the
 * dict_next() successor function, verifying that the key of each node is
 * strictly lower than that of its successor, if duplicates are allowed,
 * or lower or equal if duplicates are not allowed.  This function is used for
 * debugging purposes.
 */

static int verify_bintree(dict_t *dict)
{
    dnode_t *first, *next;

    first = dict_first(dict);

    if (dict->dupes) {
        while (first && (next = dict_next(dict, first))) {
            if (dict->compare(first->key, next->key) > 0)
                return 0;
            first = next;
        }
    } else {
        while (first && (next = dict_next(dict, first))) {
            if (dict->compare(first->key, next->key) >= 0)
                return 0;
            first = next;
        }
    }
    return 1;
}


/*
 * This function recursively verifies that the given binary subtree satisfies
 * three of the red black properties. It checks that every red node has only
 * black children. It makes sure that each node is either red or black. And it
 * checks that every path has the same count of black nodes from root to leaf.
 * It returns the blackheight of the given subtree; this allows blackheights to
 * be computed recursively and compared for left and right siblings for
 * mismatches. It does not check for every nil node being black, because there
 * is only one sentinel nil node. The return value of this function is the
 * black height of the subtree rooted at the node ``root'', or zero if the
 * subtree is not red-black.
 */

static unsigned int verify_redblack(dnode_t *nil, dnode_t *root)
{
    unsigned height_left, height_right;

    if (root != nil) {
        height_left = verify_redblack(nil, root->left);
        height_right = verify_redblack(nil, root->right);
        if (height_left == 0 || height_right == 0)
            return 0;
        if (height_left != height_right)
            return 0;
        if (root->color == dnode_red) {
            if (root->left->color != dnode_black)
                return 0;
            if (root->right->color != dnode_black)
                return 0;
            return height_left;
        }
        if (root->color != dnode_black)
            return 0;
        return height_left + 1;
    }
    return 1;
}

/*
 * Compute the actual count of nodes by traversing the tree and
 * return it. This could be compared against the stored count to
 * detect a mismatch.
 */

static dictcount_t verify_node_count(dnode_t *nil, dnode_t *root)
{
    if (root == nil)
        return 0;
    else
        return 1 + verify_node_count(nil, root->left)
            + verify_node_count(nil, root->right);
}

/*
 * Verify that the tree contains the given node. This is done by
 * traversing all of the nodes and comparing their pointers to the
 * given pointer. Returns 1 if the node is found, otherwise
 * returns zero. It is intended for debugging purposes.
 */

static int verify_dict_has_node(dnode_t *nil, dnode_t *root, dnode_t *node)
{
    if (root != nil) {
        return root == node
                || verify_dict_has_node(nil, root->left, node)
                || verify_dict_has_node(nil, root->right, node);
    }
    return 0;
}


/*
 * Dynamically allocate and initialize a dictionary object.  The safe malloc
 * routines are used for improved correctness verification.
 */

dict_t *dict_create(dictcount_t maxcount, dict_comp_t comp)
{
    dict_t *dnew = NULL;
    if ( g_dict_alloc == NULL )
       return dnew;
    dnew = (dict_t *)g_dict_alloc(sizeof *dnew);

    if (dnew) {
        dnew->compare = comp;
        dnew->allocnode = dnode_alloc;
        dnew->freenode = dnode_free;
        dnew->context = NULL;
        dnew->nodecount = 0;
        dnew->maxcount = maxcount;
        dnew->nilnode.left = &dnew->nilnode;
        dnew->nilnode.right = &dnew->nilnode;
        dnew->nilnode.parent = &dnew->nilnode;
        dnew->nilnode.color = dnode_black;
        dnew->dupes = 0;
    }
    return dnew;
}

/*
 * Select a different set of node allocator routines.
 */

void dict_set_allocator(dict_t *dict, dnode_alloc_t al,
        dnode_free_t fr, void *context)
{
#ifdef WITH_ASSERT
    assert (dict_count(dict) == 0);
#endif
/* Red Plait: why I cannot have asymmetric allocator ?
    assert ((al == 0 && fr == 0) || (al != 0 && fr != 0)); */
    dict->allocnode = al ? al : dnode_alloc;
    dict->freenode = fr ? fr : dnode_free;
    dict->context = context;
}

/*
 * Free a dynamically allocated dictionary object. Removing the nodes
 * from the tree before deleting it is required.
 */

void dict_destroy(dict_t *dict)
{
#ifdef WITH_ASSERT
    assert (dict_isempty(dict));
#endif
    g_dict_free(dict);
}

/*
 * Free all the nodes in the dictionary by using the dictionary's
 * installed free routine.
 */

extern void dict_free(dict_t *dict)
{
    dnode_t *node = dict_first(dict);

    while (node) {
        dnode_t *next = dict_next(dict, node);
        dict_delete(dict, node);
        dict->freenode(node, dict->context);
        node = next;
    }
}

/*
 * Initialize a user-supplied dictionary object.
 */

dict_t *dict_init(dict_t *dict, dictcount_t maxcount, dict_comp_t comp)
{
    dict->compare = comp;
    dict->allocnode = dnode_alloc;
    dict->freenode = dnode_free;
    dict->context = NULL;
    dict->nodecount = 0;
    dict->maxcount = maxcount;
    dict->nilnode.left = &dict->nilnode;
    dict->nilnode.right = &dict->nilnode;
    dict->nilnode.parent = &dict->nilnode;
    dict->nilnode.color = dnode_black;
    dict->dupes = 0;
    return dict;
}

/*
 * Verify the integrity of the dictionary structure.  This is provided for
 * debugging purposes, and should be placed in assert statements.   Just because
 * this function succeeds doesn't mean that the tree is not corrupt. Certain
 * corruptions in the tree may simply cause undefined behavior.
 */

int dict_verify(dict_t *dict)
{
    dnode_t *nil = dict_nil(dict), *root = dict_root(dict);

    /* check that the sentinel node and root node are black */
    if (root->color != dnode_black)
        return 0;
    if (nil->color != dnode_black)
        return 0;
    if (nil->right != nil)
        return 0;
    /* nil->left is the root node; check that its parent pointer is nil */
    if (nil->left->parent != nil)
        return 0;
    /* perform a weak test that the tree is a binary search tree */
    if (!verify_bintree(dict))
        return 0;
    /* verify that the tree is a red-black tree */
    if (!verify_redblack(nil, root))
        return 0;
    if (verify_node_count(nil, root) != dict_count(dict))
        return 0;
    return 1;
}

/*
 * Locate a node in the dictionary having the given key.
 * If the node is not found, a null a pointer is returned (rather than
 * a pointer that dictionary's nil sentinel node), otherwise a pointer to the
 * located node is returned.
 */

dnode_t *dict_lookup(dict_t *dict, const void *key)
{
    dnode_t *root = dict_root(dict);
    dnode_t *nil = dict_nil(dict);
    dnode_t *saved;
    int result;

    /* simple binary search adapted for trees that contain duplicate keys */

    while (root != nil) {
        result = dict->compare(key, root->key);
        if (result < 0)
            root = root->left;
        else if (result > 0)
            root = root->right;
        else {
            if (!dict->dupes) { /* no duplicates, return match          */
                return root;
            } else {            /* could be dupes, find leftmost one    */
                do {
                    saved = root;
                    root = root->left;
                    while (root != nil && dict->compare(key, root->key))
                        root = root->right;
                } while (root != nil);
                return saved;
            }
        }
    }

    return NULL;
}

/*
 * Look for the node corresponding to the lowest key that is equal to or
 * greater than the given key.  If there is no such node, return null.
 */

dnode_t *dict_lower_bound(dict_t *dict, void *key)
{
    dnode_t *root = dict_root(dict);
    dnode_t *nil = dict_nil(dict);
    dnode_t *tentative = 0;

    while (root != nil) {
        int result = dict->compare(key, root->key);

        if (result > 0) {
            root = root->right;
        } else if (result < 0) {
            tentative = root;
            root = root->left;
        } else {
            if (!dict->dupes) {
                return root;
            } else {
                tentative = root;
                root = root->left;
            }
        }
    }

    return tentative;
}

/*
 * Look for the node corresponding to the lowest key that is equal to or
 * greater than the given key.  If there is no such node, return null.
 */

dnode_t *dict_upper_bound(dict_t *dict, void *key)
{
    dnode_t *root = dict_root(dict);
    dnode_t *nil = dict_nil(dict);
    dnode_t *tentative = 0;

    while (root != nil) {
        int result = dict->compare(key, root->key);

        if (result < 0) {
            root = root->left;
        } else if (result > 0) {
            tentative = root;
            root = root->right;
        } else {
            if (!dict->dupes) {
                return root;
            } else {
                tentative = root;
                root = root->right;
            }
        }
    }

    return tentative;
}

/*
 * Insert a node into the dictionary. The node should have been
 * initialized with a data field. All other fields are ignored.
 * The behavior is undefined if the user attempts to insert into
 * a dictionary that is already full (for which the dict_isfull()
 * function returns true).
 */

void dict_insert(dict_t *dict, dnode_t *node, const void *key)
{
    dnode_t *where = dict_root(dict), *nil = dict_nil(dict);
    dnode_t *parent = nil, *uncle, *grandpa;
    int result = -1;

    node->key = key;

#ifdef WITH_ASSERT
    assert (!dict_isfull(dict));
    assert (!dict_contains(dict, node));
    assert (!dnode_is_in_a_dict(node));
#endif

    /* basic binary tree insert */

    while (where != nil) {
        parent = where;
        result = dict->compare(key, where->key);
        /* trap attempts at duplicate key insertion unless it's explicitly allowed */
#ifdef WITH_ASSERT
        assert (dict->dupes || result != 0);
#endif
        if (result < 0)
            where = where->left;
        else
            where = where->right;
    }

#ifdef WITH_ASSERT
    assert (where == nil);
#endif

    if (result < 0)
        parent->left = node;
    else
        parent->right = node;

    node->parent = parent;
    node->left = nil;
    node->right = nil;

    dict->nodecount++;

    /* red black adjustments */

    node->color = dnode_red;

    while (parent->color == dnode_red) {
        grandpa = parent->parent;
        if (parent == grandpa->left) {
            uncle = grandpa->right;
            if (uncle->color == dnode_red) {    /* red parent, red uncle */
                parent->color = dnode_black;
                uncle->color = dnode_black;
                grandpa->color = dnode_red;
                node = grandpa;
                parent = grandpa->parent;
            } else {                            /* red parent, black uncle */
                if (node == parent->right) {
                    rotate_left(dict, parent);
                    parent = node;
#ifdef WITH_ASSERT
                    assert (grandpa == parent->parent);
#endif
                    /* rotation between parent and child preserves grandpa */
                }
                parent->color = dnode_black;
                grandpa->color = dnode_red;
                rotate_right(dict, grandpa);
                break;
            }
        } else {        /* symmetric cases: parent == parent->parent->right */
            uncle = grandpa->left;
            if (uncle->color == dnode_red) {
                parent->color = dnode_black;
                uncle->color = dnode_black;
                grandpa->color = dnode_red;
                node = grandpa;
                parent = grandpa->parent;
            } else {
                if (node == parent->left) {
                    rotate_right(dict, parent);
                    parent = node;
#ifdef WITH_ASSERT
                    assert (grandpa == parent->parent);
#endif
                }
                parent->color = dnode_black;
                grandpa->color = dnode_red;
                rotate_left(dict, grandpa);
                break;
            }
        }
    }

    dict_root(dict)->color = dnode_black;

#ifdef WITH_ASSERT
    assert (dict_verify(dict));
#endif
}

/*
 * Delete the given node from the dictionary. If the given node does not belong
 * to the given dictionary, undefined behavior results.  A pointer to the
 * deleted node is returned.
 */

dnode_t *dict_delete(dict_t *dict, dnode_t *to_delete)
{
    dnode_t *nil = dict_nil(dict), *child, *delparent = to_delete->parent;

    /* basic deletion */

#ifdef WITH_ASSERT
    assert (!dict_isempty(dict));
    assert (dict_contains(dict, to_delete));
#endif

    /*
     * If the node being deleted has two children, then we replace it with its
     * successor (i.e. the leftmost node in the right subtree.) By doing this,
     * we avoid the traditional algorithm under which the successor's key and
     * value *only* move to the deleted node and the successor is spliced out
     * from the tree. We cannot use this approach because the user may hold
     * pointers to the successor, or nodes may be inextricably tied to some
     * other structures by way of embedding, etc. So we must splice out the
     * node we are given, not some other node, and must not move contents from
     * one node to another behind the user's back.
     */

    if (to_delete->left != nil && to_delete->right != nil) {
        dnode_t *next = dict_next(dict, to_delete);
        dnode_t *nextparent = next->parent;
        dnode_color_t nextcolor = next->color;

#ifdef WITH_ASSERT
        assert (next != nil);
        assert (next->parent != nil);
        assert (next->left == nil);
#endif

        /*
         * First, splice out the successor from the tree completely, by
         * moving up its right child into its place.
         */

        child = next->right;
        child->parent = nextparent;

        if (nextparent->left == next) {
            nextparent->left = child;
        } else {
#ifdef WITH_ASSERT
            assert (nextparent->right == next);
#endif
            nextparent->right = child;
        }

        /*
         * Now that the successor has been extricated from the tree, install it
         * in place of the node that we want deleted.
         */

        next->parent = delparent;
        next->left = to_delete->left;
        next->right = to_delete->right;
        next->left->parent = next;
        next->right->parent = next;
        next->color = to_delete->color;
        to_delete->color = nextcolor;

        if (delparent->left == to_delete) {
            delparent->left = next;
        } else {
#ifdef WITH_ASSERT
            assert (delparent->right == to_delete);
#endif
            delparent->right = next;
        }

    } else {
#ifdef WITH_ASSERT
        assert (to_delete != nil);
        assert (to_delete->left == nil || to_delete->right == nil);
#endif

        child = (to_delete->left != nil) ? to_delete->left : to_delete->right;

        child->parent = delparent = to_delete->parent;

        if (to_delete == delparent->left) {
            delparent->left = child;
        } else {
#ifdef WITH_ASSERT
            assert (to_delete == delparent->right);
#endif
            delparent->right = child;
        }
    }

    to_delete->parent = NULL;
    to_delete->right = NULL;
    to_delete->left = NULL;

    dict->nodecount--;

#ifdef WITH_ASSERT
    assert (verify_bintree(dict));
#endif

    /* red-black adjustments */

    if (to_delete->color == dnode_black) {
        dnode_t *parent, *sister;

        dict_root(dict)->color = dnode_red;

        while (child->color == dnode_black) {
            parent = child->parent;
            if (child == parent->left) {
                sister = parent->right;
#ifdef WITH_ASSERT
                assert (sister != nil);
#endif
                if (sister->color == dnode_red) {
                    sister->color = dnode_black;
                    parent->color = dnode_red;
                    rotate_left(dict, parent);
                    sister = parent->right;
#ifdef WITH_ASSERT
                    assert (sister != nil);
#endif
                }
                if (sister->left->color == dnode_black
                        && sister->right->color == dnode_black) {
                    sister->color = dnode_red;
                    child = parent;
                } else {
                    if (sister->right->color == dnode_black) {
#ifdef WITH_ASSERT
                        assert (sister->left->color == dnode_red);
#endif
                        sister->left->color = dnode_black;
                        sister->color = dnode_red;
                        rotate_right(dict, sister);
                        sister = parent->right;
#ifdef WITH_ASSERT
                        assert (sister != nil);
#endif
                    }
                    sister->color = parent->color;
                    sister->right->color = dnode_black;
                    parent->color = dnode_black;
                    rotate_left(dict, parent);
                    break;
                }
            } else {    /* symmetric case: child == child->parent->right */
#ifdef WITH_ASSERT
                assert (child == parent->right);
#endif
                sister = parent->left;
#ifdef WITH_ASSERT
                assert (sister != nil);
#endif
                if (sister->color == dnode_red) {
                    sister->color = dnode_black;
                    parent->color = dnode_red;
                    rotate_right(dict, parent);
                    sister = parent->left;
#ifdef WITH_ASSERT
                    assert (sister != nil);
#endif
                }
                if (sister->right->color == dnode_black
                        && sister->left->color == dnode_black) {
                    sister->color = dnode_red;
                    child = parent;
                } else {
                    if (sister->left->color == dnode_black) {
#ifdef WITH_ASSERT
                        assert (sister->right->color == dnode_red);
#endif
                        sister->right->color = dnode_black;
                        sister->color = dnode_red;
                        rotate_left(dict, sister);
                        sister = parent->left;
#ifdef WITH_ASSERT
                        assert (sister != nil);
#endif
                    }
                    sister->color = parent->color;
                    sister->left->color = dnode_black;
                    parent->color = dnode_black;
                    rotate_right(dict, parent);
                    break;
                }
            }
        }

        child->color = dnode_black;
        dict_root(dict)->color = dnode_black;
    }

#ifdef WITH_ASSERT
    assert (dict_verify(dict));
#endif

    return to_delete;
}

/*
 * Allocate a node using the dictionary's allocator routine, give it
 * the data item.
 */

int dict_alloc_insert(dict_t *dict, const void *key, void *data)
{
    dnode_t *node = dict->allocnode(dict->context);

    if (node) {
        dnode_init(node, data);
        dict_insert(dict, node, key);
        return 1;
    }
    return 0;
}

void dict_delete_free(dict_t *dict, dnode_t *node)
{
    dict_delete(dict, node);
    dict->freenode(node, dict->context);
}

/*
 * Return the node with the lowest (leftmost) key. If the dictionary is empty
 * (that is, dict_isempty(dict) returns 1) a null pointer is returned.
 */

dnode_t *dict_first(dict_t *dict)
{
    dnode_t *nil = dict_nil(dict), *root = dict_root(dict), *left;

    if (root != nil)
        while ((left = root->left) != nil)
            root = left;

    return (root == nil) ? NULL : root;
}

/*
 * Return the node with the highest (rightmost) key. If the dictionary is empty
 * (that is, dict_isempty(dict) returns 1) a null pointer is returned.
 */

dnode_t *dict_last(dict_t *dict)
{
    dnode_t *nil = dict_nil(dict), *root = dict_root(dict), *right;

    if (root != nil)
        while ((right = root->right) != nil)
            root = right;

    return (root == nil) ? NULL : root;
}

/*
 * Return the given node's successor node---the node which has the
 * next key in the the left to right ordering. If the node has
 * no successor, a null pointer is returned rather than a pointer to
 * the nil node.
 */

dnode_t *dict_next(dict_t *dict, dnode_t *curr)
{
    dnode_t *nil = dict_nil(dict), *parent, *left;

    if (curr->right != nil) {
        curr = curr->right;
        while ((left = curr->left) != nil)
            curr = left;
        return curr;
    }

    parent = curr->parent;

    while (parent != nil && curr == parent->right) {
        curr = parent;
        parent = curr->parent;
    }

    return (parent == nil) ? NULL : parent;
}

/*
 * Return the given node's predecessor, in the key order.
 * The nil sentinel node is returned if there is no predecessor.
 */

dnode_t *dict_prev(dict_t *dict, dnode_t *curr)
{
    dnode_t *nil = dict_nil(dict), *parent, *right;

    if (curr->left != nil) {
        curr = curr->left;
        while ((right = curr->right) != nil)
            curr = right;
        return curr;
    }

    parent = curr->parent;

    while (parent != nil && curr == parent->left) {
        curr = parent;
        parent = curr->parent;
    }

    return (parent == nil) ? NULL : parent;
}

void dict_allow_dupes(dict_t *dict)
{
    dict->dupes = 1;
}

#undef dict_count
#undef dict_isempty
#undef dict_isfull
#undef dnode_get
#undef dnode_put
#undef dnode_getkey

dictcount_t dict_count(dict_t *dict)
{
    return dict->nodecount;
}

int dict_isempty(dict_t *dict)
{
    return dict->nodecount == 0;
}

int dict_isfull(dict_t *dict)
{
    return dict->nodecount == dict->maxcount;
}

int dict_contains(dict_t *dict, dnode_t *node)
{
    return verify_dict_has_node(dict_nil(dict), dict_root(dict), node);
}

const size_t dnode_t_size = sizeof(struct dnode_t);

static dnode_t *dnode_alloc(void *context)
{
    return (dnode_t *)g_dict_alloc(dnode_t_size);
}

static void dnode_free(dnode_t *node, void *context)
{
    g_dict_free(node);
}

dnode_t *dnode_create(void *data)
{
    dnode_t *dnew = (dnode_t *)g_dict_alloc(sizeof *dnew);
    if (dnew) {
        dnew->data = data;
        dnew->parent = NULL;
        dnew->left = NULL;
        dnew->right = NULL;
    }
    return dnew;
}

dnode_t *dnode_init(dnode_t *dnode, void *data)
{
    dnode->data = data;
    dnode->parent = NULL;
    dnode->left = NULL;
    dnode->right = NULL;
    return dnode;
}

void dnode_destroy(dnode_t *dnode)
{
#ifdef WITH_ASSERT
    assert (!dnode_is_in_a_dict(dnode));
#endif
    g_dict_free(dnode);
}

void *dnode_get(dnode_t *dnode)
{
    return dnode->data;
}

const void *dnode_getkey(dnode_t *dnode)
{
    return dnode->key;
}

void dnode_put(dnode_t *dnode, void *data)
{
    dnode->data = data;
}

int dnode_is_in_a_dict(dnode_t *dnode)
{
    return (dnode->parent && dnode->left && dnode->right);
}

void dict_process(dict_t *dict, void *context, dnode_process_t function)
{
    dnode_t *node = dict_first(dict), *next;

    while (node != NULL) {
        /* check for callback function deleting */
        /* the next node from under us          */
#ifdef WITH_ASSERT
        assert (dict_contains(dict, node));
#endif
        next = dict_next(dict, node);
        function(dict, node, context);
        node = next;
    }

}


#ifdef KAZLIB_TEST_MAIN

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>

typedef char input_t[256];

static int tokenize(char *string, ...)
{
    char **tokptr;
    va_list arglist;
    int tokcount = 0;

    va_start(arglist, string);
    tokptr = va_arg(arglist, char **);
    while (tokptr) {
        while (*string && isspace((unsigned char) *string))
            string++;
        if (!*string)
            break;
        *tokptr = string;
        while (*string && !isspace((unsigned char) *string))
            string++;
        tokptr = va_arg(arglist, char **);
        tokcount++;
        if (!*string)
            break;
        *string++ = 0;
    }
    va_end(arglist);

    return tokcount;
}

static int comparef(const void *key1, const void *key2)
{
    return strcmp(key1, key2);
}

static char *dupstring(char *str)
{
    int sz = strlen(str) + 1;
    char *new = malloc(sz);
    if (new)
        memcpy(new, str, sz);
    return new;
}

static dnode_t *new_node(void *c)
{
    static dnode_t few[5];
    static int count;

    if (count < 5)
        return few + count++;

    return NULL;
}

static void del_node(dnode_t *n, void *c)
{
}

int main(void)
{
    input_t in;
    dict_t *d = dict_create(DICTCOUNT_T_MAX, comparef);
    dnode_t *dn;
    char *tok1, *tok2, *val;
    const char *key;
    int prompt = 0;

    char *help =
        "a <key> <val>          add value to dictionary\n"
        "d <key>                delete value from dictionary\n"
        "l <key>                lookup value in dictionary\n"
        "( <key>                lookup lower bound\n"
        ") <key>                lookup upper bound\n"
        "k                      allow duplicate keys\n"
        "c                      show number of entries\n"
        "t                      dump whole dictionary in sort order\n"
        "p                      turn prompt on\n"
        "s                      switch to non-functioning allocator\n"
        "q                      quit";

    if (!d)
        puts("dict_create failed");

    for (;;) {
        if (prompt)
            putchar('>');
        fflush(stdout);

        if (!fgets(in, sizeof(input_t), stdin))
            break;

        switch(in[0]) {
            case '?':
                puts(help);
                break;
            case 'a':
                if (tokenize(in+1, &tok1, &tok2, (char **) 0) != 2) {
                    puts("what?");
                    break;
                }
                key = dupstring(tok1);
                val = dupstring(tok2);

                if (!key || !val) {
                    puts("out of memory");
                    free((void *) key);
                    free(val);
                }

                if (!dict_alloc_insert(d, key, val)) {
                    puts("dict_alloc_insert failed");
                    free((void *) key);
                    free(val);
                    break;
                }
                break;
            case 'd':
                if (tokenize(in+1, &tok1, (char **) 0) != 1) {
                    puts("what?");
                    break;
                }
                dn = dict_lookup(d, tok1);
                if (!dn) {
                    puts("dict_lookup failed");
                    break;
                }
                val = dnode_get(dn);
                key = dnode_getkey(dn);
                dict_delete_free(d, dn);

                free(val);
                free((void *) key);
                break;
            case 'l':
            case '(':
            case ')':
                if (tokenize(in+1, &tok1, (char **) 0) != 1) {
                    puts("what?");
                    break;
                }
                dn = 0;
                switch (in[0]) {
                case 'l':
                    dn = dict_lookup(d, tok1);
                    break;
                case '(':
                    dn = dict_lower_bound(d, tok1);
                    break;
                case ')':
                    dn = dict_upper_bound(d, tok1);
                    break;
                }
                if (!dn) {
                    puts("lookup failed");
                    break;
                }
                val = dnode_get(dn);
                puts(val);
                break;
            case 'k':
                dict_allow_dupes(d);
                break;
            case 'c':
                printf("%lu\n", (unsigned long) dict_count(d));
                break;
            case 't':
                for (dn = dict_first(d); dn; dn = dict_next(d, dn)) {
                    printf("%s\t%s\n", (char *) dnode_getkey(dn),
                            (char *) dnode_get(dn));
                }
                break;
            case 'q':
                exit(0);
                break;
            case '\0':
                break;
            case 'p':
                prompt = 1;
                break;
            case 's':
                dict_set_allocator(d, new_node, del_node, NULL);
                break;
            default:
                putchar('?');
                putchar('\n');
                break;
        }
    }

    return 0;
}

#endif
