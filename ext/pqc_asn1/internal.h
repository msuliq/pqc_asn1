/*
 * internal.h — private definitions shared across libpqcsb source files.
 *
 * This header is NOT installed and is NOT part of the public API.
 */

#ifndef PQCSB_INTERNAL_H
#define PQCSB_INTERNAL_H

/* Include generated config before anything else. */
#include "pqcsb_config.h"

/* Enable memset_s() on Apple/BSD via C11 Annex K.
 * Must appear before any system header that may include string.h. */
#ifndef __STDC_WANT_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif

#include "pqcsb.h"

#include <string.h>
#include <stdio.h>
#include <stdatomic.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#ifdef _WIN32
#include <windows.h>
#include <ntsecapi.h>
#endif

/* ------------------------------------------------------------------ */
/* MAP_ANONYMOUS portability                                           */
/* ------------------------------------------------------------------ */

#if defined(HAVE_MMAP) && !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif

/* ------------------------------------------------------------------ */
/* Platform backend selection                                          */
/* ------------------------------------------------------------------ */

#if defined(HAVE_MMAP) && defined(MAP_ANONYMOUS)
#  define PQCSB_USE_MMAP 1
#elif defined(_WIN32)
#  define PQCSB_USE_VIRTUALALLOC 1
#elif defined(PQCSB_ALLOW_MALLOC_FALLBACK)
   /* Weak protection: canaries only, no guard pages, no mprotect */
#else
#  error "No mmap or VirtualAlloc available. Define PQCSB_ALLOW_MALLOC_FALLBACK "\
         "to opt into the malloc fallback (no guard pages — reduced security guarantees)."
#endif

/* ------------------------------------------------------------------ */
/* Protection macros                                                   */
/* ------------------------------------------------------------------ */

#if defined(PQCSB_USE_MMAP) && defined(HAVE_MPROTECT)
#  define PQCSB_SET_PROT(base, ps, dp, prot) \
       mprotect((base) + (ps), (dp), (prot))
#  define PQCSB_PROT_NONE   PROT_NONE
#  define PQCSB_PROT_READ   PROT_READ
#  define PQCSB_PROT_RW     (PROT_READ | PROT_WRITE)
#  define PQCSB_HAS_PROTECT 1
#elif defined(PQCSB_USE_VIRTUALALLOC)
#  define PQCSB_SET_PROT(base, ps, dp, prot) do { \
       DWORD _old; \
       VirtualProtect((base) + (ps), (dp), (prot), &_old); \
   } while (0)
#  define PQCSB_PROT_NONE   PAGE_NOACCESS
#  define PQCSB_PROT_READ   PAGE_READONLY
#  define PQCSB_PROT_RW     PAGE_READWRITE
#  define PQCSB_HAS_PROTECT 1
#else
#  define PQCSB_HAS_PROTECT 0
#endif

/* ------------------------------------------------------------------ */
/* Buffer struct (opaque to consumers)                                 */
/* ------------------------------------------------------------------ */

struct pqcsb_buf {
    uint8_t *data;          /* pointer to user data (inside mmap or malloc'd) */
    size_t   len;           /* user-requested byte length */
    uint8_t *mmap_base;     /* base of entire mmap region (NULL if malloc) */
    size_t   mmap_len;      /* total mmap size including guard pages */
    size_t   data_pages;    /* size of data region (between guard pages) */
    int      wiped;         /* 1 if wipe() was called */
    int      locked;        /* 1 if mlock succeeded on the data pages */
    _Atomic int read_refs;  /* reference count for nested begin_read/end_read */
    uint8_t  canary[PQCSB_CANARY_SIZE]; /* per-buffer random canary */
    pqcsb_config_t config;  /* runtime configuration options for this buffer */
};

/* ------------------------------------------------------------------ */
/* Internal function declarations                                      */
/* ------------------------------------------------------------------ */

/* secure_zero.c */
/* (pqcsb_secure_zero is public, declared in pqcsb.h) */

/* random.c */
/* (pqcsb_fill_random is public, declared in pqcsb.h) */

#endif /* PQCSB_INTERNAL_H */
