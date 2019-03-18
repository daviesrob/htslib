/*
Copyright (c) 2013-2018 Genome Research Ltd.
Authors: James Bonfield <jkb@sanger.ac.uk>, Valeriu Ohan <vo2@sanger.ac.uk>

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

   3. Neither the names Genome Research Ltd and Wellcome Trust Sanger
Institute nor the names of its contributors may be used to endorse or promote
products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY GENOME RESEARCH LTD AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL GENOME RESEARCH LTD OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*! \file
 * SAM header parsing.
 *
 * These functions can be shared between SAM, BAM and CRAM file
 * formats as all three internally use the same string encoding for
 * header fields.
 */


#ifndef HEADER_H_
#define HEADER_H_

#include <stdarg.h>

#include "cram/string_alloc.h"
#include "cram/pooled_alloc.h"

#include "htslib/khash.h"
#include "htslib/kstring.h"
#include "htslib/sam.h"

#define SAM_HDR_LINES 32

#ifdef __cplusplus
extern "C" {
#endif

// For structure assignment. Eg kstring_t s = KS_INITIALIZER;
#define KS_INITIALIZER {0,0,0}

// For initialisation elsewhere. Eg KS_INIT(x->str);
#define KS_INIT(ks) ((ks)->l = 0, (ks)->m = 0, (ks)->s = NULL)

// Frees the string subfield only. Assumes 's' itself is static.
#define KS_FREE(ks) do { if ((ks)->s) {free((ks)->s); (ks)->s = NULL;} } while(0)

#define K(a) (((a)[0]<<8)|((a)[1]))

/*
 * Proposed new SAM header parsing

1 @SQ ID:foo LN:100
2 @SQ ID:bar LN:200
3 @SQ ID:ram LN:300 UR:xyz
4 @RG ID:r ...
5 @RG ID:s ...

Hash table for 2-char @keys without dup entries.
If dup lines, we form a circular linked list. Ie hash keys = {RG, SQ}.

HASH("SQ")--\
            |
    (3) <-> 1 <-> 2 <-> 3 <-> (1)

HASH("RG")--\
            |
    (5) <-> 4 <-> 5 <-> (4)

Items stored in the hash values also form their own linked lists:
Ie SQ->ID(foo)->LN(100)
   SQ->ID(bar)->LN(200)
   SQ->ID(ram)->LN(300)->UR(xyz)
   RG->ID(r)
 */

/*! A single key:value pair on a header line
 *
 * These form a linked list and hold strings. The strings are
 * allocated from a string_alloc_t pool referenced in the master
 * sam_hdr_t structure. Do not attempt to free, malloc or manipulate
 * these strings directly.
 */
typedef struct sam_hdr_tag_s {
    struct sam_hdr_tag_s *next;
    char *str;
    int   len;
} sam_hdr_tag_t;

/*! The parsed version of the SAM header string.
 *
 * Each header type (SQ, RG, HD, etc) points to its own sam_hdr_type
 * struct via the main hash table h in the sam_hdr_t struct.
 *
 * These in turn consist of circular bi-directional linked lists (ie
 * rings) to hold the multiple instances of the same header type
 * code. For example if we have 5 \@SQ lines the primary hash table
 * will key on \@SQ pointing to the first sam_hdr_type and that in turn
 * will be part of a ring of 5 elements.
 *
 * For each sam_hdr_type structure we also point to a sam_hdr_tag
 * structure which holds the tokenised attributes; the tab separated
 * key:value pairs per line.
 */
typedef struct sam_hdr_type_s {
    struct sam_hdr_type_s *next; // circular
    struct sam_hdr_type_s *prev;
    sam_hdr_tag_t *tag;          // first tag
    int order;                   // 0 upwards
    int skip;                    // 1 - don't add this line to the header text together with all the others from the same type.
                                 // Useful for comments.
    struct sam_hdr_type_s *comm; // attached comment line
} sam_hdr_type_t;

/*! Parsed \@SQ lines */
typedef struct {
    char *name;
    uint32_t len;
    sam_hdr_type_t *ty;
    sam_hdr_tag_t  *tag;
} sam_hdr_sq_t;

/*! Parsed \@RG lines */
typedef struct {
    char *name;
    sam_hdr_type_t *ty;
    sam_hdr_tag_t  *tag;
    int name_len;
    int id;           // numerical ID
} sam_hdr_rg_t;

/*! Parsed \@PG lines */
typedef struct {
    char *name;
    sam_hdr_type_t *ty;
    sam_hdr_tag_t  *tag;
    int name_len;
    int id;           // numerical ID
    int prev_id;      // -1 if none
} sam_hdr_pg_t;


/*! Sort order parsed from @HD line */
enum sam_sort_order {
    ORDER_UNKNOWN  =-1,
    ORDER_UNSORTED = 0,
    ORDER_NAME     = 1,
    ORDER_COORD    = 2
  //ORDER_COLLATE  = 3 // maybe one day!
};

enum sam_group_order {
    ORDER_NONE      =-1,
    ORDER_QUERY     = 0,
    ORDER_REFERENCE = 1
};

KHASH_MAP_INIT_INT(sam_hdr_t, sam_hdr_type_t*)
KHASH_MAP_INIT_STR(m_s2i, int)

/*! Primary structure for header manipulation
 *
 * The initial header text is held in the text kstring_t, but is also
 * parsed out into SQ, RG and PG arrays. These have a hash table
 * associated with each to allow lookup by ID or SN fields instead of
 * their numeric array indices. Additionally PG has an array to hold
 * the linked list start points (the last in a PP chain).
 *
 * Use the appropriate sam_hdr_* functions to edit the header, and
 * call sam_hdr_rebuild() any time the textual form needs to be
 * updated again.
 */
struct sam_hdr {
    khash_t(sam_hdr_t) *h;
    string_alloc_t *str_pool; //!< Pool of sam_hdr_tag->str strings
    pool_alloc_t   *type_pool;//!< Pool of sam_hdr_type structs
    pool_alloc_t   *tag_pool; //!< Pool of sam_hdr_tag structs

    // @SQ lines / references
    int nref;                 //!< Number of \@SQ lines
    sam_hdr_sq_t *ref;              //!< Array of parsed \@SQ lines
    khash_t(m_s2i) *ref_hash; //!< Maps SQ SN field to ref[] index

    // @RG lines / read-groups
    int nrg;                  //!< Number of \@RG lines
    sam_hdr_rg_t *rg;               //!< Array of parsed \@RG lines
    khash_t(m_s2i) *rg_hash;  //!< Maps RG ID field to rg[] index

    // @PG lines / programs
    int npg;                  //!< Number of \@PG lines
    int npg_end;              //!< Number of terminating \@PG lines
    int npg_end_alloc;        //!< Size of pg_end field
    sam_hdr_pg_t *pg;               //!< Array of parsed \@PG lines
    khash_t(m_s2i) *pg_hash;  //!< Maps PG ID field to pg[] index
    int *pg_end;              //!< \@PG chain termination IDs

    // @cond internal
    char ID_buf[1024];  // temporary buffer
    int ID_cnt;
    int ref_count;      // number of uses of this sam_hdr_t
    // @endcond

    int dirty;                // marks the header as modified, so it can be rebuilt
    int refs_changed;   // Index of first changed ref (-1 if unchanged)
    int type_count;
    char (*type_order)[3];
};

/*! Populate the internal SAM header from the header text.
 *
 * @return
 * Returns -1 on error, 0 on success
 */
int sam_hdr_populate(bam_hdr_t *bh);

/*! Creates an empty SAM header, ready to be populated.
 *
 * @return
 * Returns a sam_hdr_t struct on success (free with sam_hdr_destroy())
 *         NULL on failure
 */
sam_hdr_t *sam_hdr_new(void);

/*!
 * Allocates space for the rest of the SAM header structures (hash tables), to prepare for
 * processing. This method is decoupled from sam_hdr_new because some operations do not
 * process the header, hence no need of parsing the text.
 *
 * @return
 * Returns -1 on error, 0 on success
 *
 */
int sam_hdr_init(sam_hdr_t *sh);

/*! Produces a duplicate copy of hdr and returns it.
 * @return
 * Returns NULL on failure
 */
sam_hdr_t *sam_hdr_dup(sam_hdr_t *hdr);

/*! Update bam_hdr_t target_name and target_len arrays
 *
 *  bam_hdr_t and sam_hdr_t are specified separately so that bam_hdr_dup
 *  can use it to construct target arrays from the source header.
 *
 *  @return 0 on success; -1 on failure
 */
int update_target_arrays(bam_hdr_t *bh, const sam_hdr_t *sh,
                         int refs_changed);

/*! Reconstructs a kstring from the header hash table.
 *
 * @return
 * Returns 0 on success
 *        -1 on failure
 */
int sam_hdr_rebuild_text(const sam_hdr_t *sh, kstring_t *ks);

/*! Deallocates all storage used by a sam_hdr_t struct.
 *
 * This also decrements the header reference count. If after decrementing
 * it is still non-zero then the header is assumed to be in use by another
 * caller and the free is not done.
 *
 * This is a synonym for sam_hdr_dec_ref().
 */
void sam_hdr_destroy(sam_hdr_t *hdr);

/*!
 * @return
 * Returns the first header item matching 'type'. If ID is non-NULL it checks
 * for the tag ID: and compares against the specified ID.
 *
 * Returns NULL if no type/ID is found
 */
sam_hdr_type_t *sam_hdr_find_type(sam_hdr_t *hdr, const char *type,
                           const char *ID_key, const char *ID_value);

/*
 * Adds or updates tag key,value pairs in a header line.
 * Eg for adding M5 tags to @SQ lines or updating sort order for the
 * @HD line.
 *
 * Specify multiple key,value pairs ending in NULL.
 *
 * Returns 0 on success
 *        -1 on failure
 */
int sam_hdr_update(sam_hdr_t *sh, sam_hdr_type_t *type, va_list ap);

sam_hdr_tag_t *sam_hdr_find_key(sam_hdr_type_t *type,
                              const char *key,
                              sam_hdr_tag_t **prev);

int sam_hdr_remove_key(sam_hdr_t *sh,
                       sam_hdr_type_t *type,
                       const char *key);

/*! Looks up a read-group by name and returns a pointer to the start of the
 * associated tag list.
 *
 * @return
 * Returns NULL on failure
 */
sam_hdr_rg_t *sam_hdr_find_rg(sam_hdr_t *hdr, const char *rg);

/*! Increments a reference count on hdr.
 *
 * This permits multiple files to share the same header, all calling
 * sam_hdr_free when done, without causing errors for other open  files.
 */
void sam_hdr_incr_ref(sam_hdr_t *sh);

/*! Increments a reference count on hdr.
 *
 * This permits multiple files to share the same header, all calling
 * sam_hdr_free when done, without causing errors for other open  files.
 *
 * If the reference count hits zero then the header is automatically
 * freed. This makes it a synonym for sam_hdr_free().
 */
void sam_hdr_decr_ref(sam_hdr_t *sh);

/*! Returns the sort order from the @HD SO: field */
enum sam_sort_order sam_hdr_sort_order(sam_hdr_t *hdr);

/*! Returns the group order from the @HD SO: field */
enum sam_group_order sam_hdr_group_order(sam_hdr_t *hdr);

#ifdef __cplusplus
}
#endif

#endif /* HEADER_H_ */
