/*
 * A heap "generic" or "template" in C.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002 MontaVista Software Inc.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License
 *  as published by the Free Software Foundation; either version 2 of
 *  the License, or (at your option) any later version.
 *
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 *  OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 *  TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 *  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * This is a heap C "generic", it allows you to define a heap for a
 * given type.  To us this, create a file with something like:
 *
 * typedef struct heap_val_s { int a; } heap_val_t; -- The included element
 *
 * #define heap_node_s test_heap_node_s -- This is the name of the heap
 *                                         element's structure.
 * #define heap_s test_heap_s -- This is the name of the heap type.
 * #define HEAP_EXPORT_NAME(s) test_ ## s -- This will prepend all the
 *                                           names with a string, here
 *                                           "test_".
 * #define HEAP_NAMES_LOCAL static  -- This is only if you want the symbols
 *                                     defined here to be local
 * static int
 * heap_cmp_key(heap_t val1, heap_t val2)
 * {
 *     if (val1.a < val2.a) {
 * 	   return -1;
 *     } else if (val1.a > val2.a) {
 * 	   return 1;
 *     } else {
 * 	   return 0;
 *    }
 * }
 * #include <heap.h>
 *
 * The included element heap_val_t and the comparison function
 * heap_cmp_key may be #define's if you desire.
 *
 * The heap.h code will create a structure with the name defined by
 * heap_node_s that contains the element "val", which is heap_val_t.
 * It also contains other items you should not touch.  The heap_node_s
 * structure is what you deal with.
 *
 * It will also create a structure with the named defined by heap_s
 * for the heap itself.
 *
 * The following functions are created, where xxx_ is the value you
 * give to HEAP_EXPORT_NAME():
 *
 * void xxx_init(sruct heap_s *heap);
 * struct heap_node_s *xxx_get_top(sruct heap_s *heap);
 * void xxx_add(struct heap_s *heap, struct heap_node_s *elem);
 * void xxx_remove(struct heap_s *heap, struct heap_node_s *elem);
 *
 * To use the heap, first define or allocate a struct heap_s, and call
 * xxx_init() with it.
 *
 * To add an element to the heap, allocate a struct heap_node_s, fill
 * in your values, and then call xxx_add(heap, elem).  You can only add
 * an element to the heap once.
 *
 * To remove an element, pass it in to xxx_remove(heap, elem).  Then
 * you may free the element.
 *
 * The heap does not track membership, so be sure that the element
 * belongs to the proper heap.
 *
 * If you define HEAP_DEBUG, you also need to define the following:
 *
 * #define HEAP_OUTPUT_PRINTF "(%d)"
 * #define HEAP_OUTPUT_DATA pos->val.a
 * */

struct heap_node_s
{
    heap_val_t val;

    /* Links for the heap. */
    struct heap_node_s *left, *right, *up;
};

struct heap_s
{
    struct heap_node_s *top, *last;
};


#ifndef HEAP_NAMES_LOCAL
#define HEAP_NAMES_LOCAL
#endif


#ifdef HEAP_DEBUG
#include <stdio.h>
static FILE **HEAP_EXPORT_NAME(debug_out) = &stderr;

static void
HEAP_EXPORT_NAME(print_item)(struct heap_node_s *pos, int indent)
{
    int i;
    for (i = 0; i < indent; i++)
	fprintf(*HEAP_EXPORT_NAME(debug_out), " ");
    fprintf(*HEAP_EXPORT_NAME(debug_out),
	    "  %p: %p %p %p " HEAP_OUTPUT_PRINTF "\n",
	    pos, pos->left, pos->right, pos->up, HEAP_OUTPUT_DATA);
    if (pos->left)
	HEAP_EXPORT_NAME(print_item)(pos->left, indent + 1);
    if (pos->right)
	HEAP_EXPORT_NAME(print_item)(pos->right, indent + 1);
}

static void
HEAP_EXPORT_NAME(print)(struct heap_s *heap)
{
    fprintf(*HEAP_EXPORT_NAME(debug_out), "top=%p\n", heap->top);
    if (heap->top)
	HEAP_EXPORT_NAME(print_item)(heap->top, 0);
    fprintf(*HEAP_EXPORT_NAME(debug_out), "last=%p\n", heap->last);
    fflush(*HEAP_EXPORT_NAME(debug_out));
}

static void
HEAP_EXPORT_NAME(check_item)(struct heap_node_s *curr,
			     unsigned int       *depth,
			     unsigned int       max_depth,
			     struct heap_node_s **real_last,
			     int                *found_last)
{
    if (! curr->left) {
	if (curr->right) {
	    fprintf(*HEAP_EXPORT_NAME(debug_out), "Tree corrupt B\n");
	    *((int *) NULL) = 0;
	} else if (*depth > max_depth) {
	    fprintf(*HEAP_EXPORT_NAME(debug_out), "Tree corrupt C\n");
	    *((int *) NULL) = 0;
	} else if ((*depth + 1) < max_depth) {
	    fprintf(*HEAP_EXPORT_NAME(debug_out), "Tree corrupt D\n");
	    *((int *) NULL) = 0;
	} else if ((*found_last) && (*depth == max_depth)) {
	    fprintf(*HEAP_EXPORT_NAME(debug_out), "Tree corrupt E\n");
	    *((int *) NULL) = 0;
	} else if (*depth == max_depth) {
	    *real_last = curr;
	} else {
	    *found_last = 1;
	}
    } else {
	if (curr->left->up != curr) {
	    fprintf(*HEAP_EXPORT_NAME(debug_out), "Tree corrupt I\n");
	    *((int *) NULL) = 0;
	}
	if (heap_cmp_key(&(curr->left->val), &(curr->val)) < 0) {
	    fprintf(*HEAP_EXPORT_NAME(debug_out), "Tree corrupt K\n");
	    *((int *) NULL) = 0;
	}
	(*depth)++;
	HEAP_EXPORT_NAME(check_item)(curr->left,
				     depth,
				     max_depth,
				     real_last,
				     found_last);
	(*depth)--;

	if (! curr->right) {
	    if (*depth != (max_depth - 1)) {
		fprintf(*HEAP_EXPORT_NAME(debug_out), "Tree corrupt F\n");
		*((int *) NULL) = 0;
	    }
	    if (*found_last) {
		fprintf(*HEAP_EXPORT_NAME(debug_out), "Tree corrupt G\n");
		*((int *) NULL) = 0;
	    }
	    *found_last = 1;
	} else {
	    if (curr->right->up != curr) {
		fprintf(*HEAP_EXPORT_NAME(debug_out), "Tree corrupt H\n");
		*((int *) NULL) = 0;
	    }
	    if (heap_cmp_key(&(curr->right->val), &(curr->val)) < 0) {
		fprintf(*HEAP_EXPORT_NAME(debug_out), "Tree corrupt L\n");
		*((int *) NULL) = 0;
	    }
	    (*depth)++;
	    HEAP_EXPORT_NAME(check_item)(curr->right,
					 depth,
					 max_depth,
					 real_last,
					 found_last);
	    (*depth)--;
	}
    }
}

static void
HEAP_EXPORT_NAME(check)(struct heap_s *heap)
{
    unsigned int        depth = 0, max_depth = 0;
    int                 found_last = 0;
    struct heap_node_s  *real_last;

    if (!heap->top) {
	if (heap->last) {
	    fprintf(*HEAP_EXPORT_NAME(debug_out), "Tree corrupt A\n");
	    *((int *) NULL) = 0;
	}
	return;
    }

    real_last = heap->top;
    while (real_last->left) {
	real_last = real_last->left;
	max_depth++;
    }

    real_last = NULL;
    HEAP_EXPORT_NAME(check_item)(heap->top,
				 &depth,
				 max_depth,
				 &real_last,
				 &found_last);

    if (real_last != heap->last) {
	fprintf(*HEAP_EXPORT_NAME(debug_out), "Tree corrupt J\n");
	*((int *) NULL) = 0;
    }
    fflush(*HEAP_EXPORT_NAME(debug_out));
}
#endif

static void
HEAP_EXPORT_NAME(find_next_pos)(struct heap_node_s *curr,
				struct heap_node_s ***next,
				struct heap_node_s **parent)
{
    unsigned int upcount = 0;

    if (curr->up && (curr->up->left == curr)) {
	/* We are a left node, the next node is just my right partner. */
	*next = &(curr->up->right);
	*parent = curr->up;
	return;
    }

    /* While we are a right node, go up. */
    while (curr->up && (curr->up->right == curr)) {
	upcount++;
	curr = curr->up;
    }

    if (curr->up) {
	/* Now we are a left node, trace up then back down. */
	curr = curr->up->right;
	upcount--;
    }
    while (upcount) {
	curr = curr->left;
	upcount--;
    }
    *next = &(curr->left);
    *parent = curr;
}

static void
HEAP_EXPORT_NAME(find_prev_elem)(struct heap_node_s *curr, struct heap_node_s **prev)
{
    unsigned int upcount = 0;

    if (curr->up && (curr->up->right == curr)) {
	/* We are a right node, the previous node is just my left partner. */
	*prev = curr->up->left;
	return;
    }

    /* While we are a left node, go up. */
    while (curr->up && (curr->up->left == curr)) {
	upcount++;
	curr = curr->up;
    }

    if (curr->up) {
	/* Now we are a right node, trace up then back down. */
	curr = curr->up->left;
    } else {
	/* We are going to the previous "row". */
	upcount--;
    }
    while (upcount) {
	curr = curr->right;
	upcount--;
    }
    *prev = curr;
}

static void
HEAP_EXPORT_NAME(send_up)(struct heap_node_s *elem,
			  struct heap_node_s **top,
			  struct heap_node_s **last)
{
    struct heap_node_s *tmp1, *tmp2, *parent;

    parent = elem->up;
    while (parent && (heap_cmp_key(&elem->val, &parent->val) < 0)) {
	tmp1 = elem->left;
	tmp2 = elem->right;
	if (parent->left == elem) {
	    elem->left = parent;
	    elem->right = parent->right;
	    if (elem->right)
		elem->right->up = elem;
	} else {
	    elem->right = parent;
	    elem->left = parent->left;
	    if (elem->left)
		elem->left->up = elem;
	}
	elem->up = parent->up;

	if (parent->up) {
	    if (parent->up->left == parent) {
		parent->up->left = elem;
	    } else {
		parent->up->right = elem;
	    }
	} else {
	    *top = elem;
	}

	parent->up = elem;
	parent->left = tmp1;
	if (parent->left)
	    parent->left->up = parent;
	parent->right = tmp2;
	if (parent->right)
	    parent->right->up = parent;

	if (*last == elem)
	    *last = parent;

	parent = elem->up;
    }
}

static void
HEAP_EXPORT_NAME(send_down)(struct heap_node_s *elem,
			    struct heap_node_s **top,
			    struct heap_node_s **last)
{
    struct heap_node_s *tmp1, *tmp2, *left, *right;

    left = elem->left;
    while (left) {
	right = elem->right;
	/* Choose the smaller of the two below me to swap with. */
	if ((right) && (heap_cmp_key(&left->val, &right->val) > 0)) {

	    if (heap_cmp_key(&elem->val, &right->val) > 0) {
		/* Swap with the right element. */
		tmp1 = right->left;
		tmp2 = right->right;
		if (elem->up) {
		    if (elem->up->left == elem) {
			elem->up->left = right;
		    } else {
			elem->up->right = right;
		    }
		} else {
		    *top = right;
		}
		right->up = elem->up;
		elem->up = right;

		right->left = elem->left;
		right->right = elem;
		elem->left = tmp1;
		elem->right = tmp2;
		if (right->left)
		    right->left->up = right;
		if (elem->left)
		    elem->left->up = elem;
		if (elem->right)
		    elem->right->up = elem;

		if (*last == right)
		    *last = elem;
	    } else
		goto done;
	} else {
	    /* The left element is smaller, or the right doesn't exist. */
	    if (heap_cmp_key(&elem->val, &left->val) > 0) {
		/* Swap with the left element. */
		tmp1 = left->left;
		tmp2 = left->right;
		if (elem->up) {
		    if (elem->up->left == elem) {
			elem->up->left = left;
		    } else {
			elem->up->right = left;
		    }
		} else {
		    *top = left;
		}
		left->up = elem->up;
		elem->up = left;

		left->left = elem;
		left->right = elem->right;
		elem->left = tmp1;
		elem->right = tmp2;
		if (left->right)
		    left->right->up = left;
		if (elem->left)
		    elem->left->up = elem;
		if (elem->right)
		    elem->right->up = elem;

		if (*last == left)
		    *last = elem;
	    } else
		goto done;
	}
	left = elem->left;
    }
done:
    return;
}

HEAP_NAMES_LOCAL void
HEAP_EXPORT_NAME(add)(struct heap_s *heap, struct heap_node_s *elem)
{
    struct heap_node_s **next;
    struct heap_node_s *parent;

#ifdef HEAP_MASSIVE_DEBUG
    fprintf(*HEAP_EXPORT_NAME(debug_out),
	    "HEAP_EXPORT_NAME(add_to_heap) entry\n");
    HEAP_EXPORT_NAME(print)(heap->top, heap->last);
    HEAP_EXPORT_NAME(check)(heap->top, heap->last);
#endif

    elem->left = NULL;
    elem->right = NULL;
    elem->up = NULL;

    if (heap->top == NULL) {
	heap->top = elem;
	heap->last = elem;
	goto out;
    }

    HEAP_EXPORT_NAME(find_next_pos)(heap->last, &next, &parent);
    *next = elem;
    elem->up = parent;
    heap->last = elem;
    if (heap_cmp_key(&elem->val, &parent->val) < 0) {
	HEAP_EXPORT_NAME(send_up)(elem, &(heap->top), &(heap->last));
    }

 out:
#ifdef HEAP_MASSIVE_DEBUG
    fprintf(*HEAP_EXPORT_NAME(debug_out),
	    "HEAP_EXPORT_NAME(add_to_heap) exit\n");
    HEAP_EXPORT_NAME(print)(heap->top, heap->last);
    HEAP_EXPORT_NAME(check)(heap->top, heap->last);
#endif
    return;
}

HEAP_NAMES_LOCAL void
HEAP_EXPORT_NAME(remove)(struct heap_s *heap, struct heap_node_s *elem)
{
    struct heap_node_s *to_insert;

#ifdef HEAP_MASSIVE_DEBUG
    fprintf(*HEAP_EXPORT_NAME(debug_out),
	    "HEAP_EXPORT_NAME(remove_from_heap) entry\n");
    HEAP_EXPORT_NAME(print)(heap->top, heap->last);
    HEAP_EXPORT_NAME(check)(heap->top, heap->last);
#endif

    /* First remove the last element from the tree, if it's not what's
       being removed, we will use it for insertion into the removal
       place. */
    to_insert = heap->last;
    if (! to_insert->up) {
	/* This is the only element in the heap. */
	heap->top = NULL;
	heap->last = NULL;
	goto out;
    } else {
	/* Set the new last position, and remove the item we will
           insert. */
	HEAP_EXPORT_NAME(find_prev_elem)(to_insert, &(heap->last));
	if (to_insert->up->left == to_insert) {
	    to_insert->up->left = NULL;
	} else {
	    to_insert->up->right = NULL;
	}
    }

    if (elem == to_insert) {
	/* We got lucky and removed the last element.  We are done. */
	goto out;
    }

    /* Now stick the formerly last element into the removed element's
       position. */
    if (elem->up) {
	if (elem->up->left == elem) {
	    elem->up->left = to_insert;
	} else {
	    elem->up->right = to_insert;
	}
    } else {
	/* The head of the tree is being replaced. */
	heap->top = to_insert;
    }
    to_insert->up = elem->up;
    if (elem->left)
	elem->left->up = to_insert;
    if (elem->right)
	elem->right->up = to_insert;
    to_insert->left = elem->left;
    to_insert->right = elem->right;

    if (heap->last == elem)
	heap->last = to_insert;

    elem = to_insert;

    /* Now propigate it to the right place in the tree. */
    if (elem->up && heap_cmp_key(&elem->val, &elem->up->val) < 0) {
	HEAP_EXPORT_NAME(send_up)(elem, &(heap->top), &(heap->last));
    } else {
	HEAP_EXPORT_NAME(send_down)(elem, &(heap->top), &(heap->last));
    }

 out:
#ifdef HEAP_MASSIVE_DEBUG
    fprintf(*HEAP_EXPORT_NAME(debug_out), "remove_from_head exit\n");
    HEAP_EXPORT_NAME(print)(heap->top, heap->last);
    HEAP_EXPORT_NAME(check)(heap->top, heap->last);
#endif
    return;
}

HEAP_NAMES_LOCAL struct heap_node_s *
HEAP_EXPORT_NAME(get_top)(struct heap_s *heap)
{
    return heap->top;
}

HEAP_NAMES_LOCAL void
HEAP_EXPORT_NAME(init)(struct heap_s *heap)
{
    heap->top = NULL;
    heap->last = NULL;
}
