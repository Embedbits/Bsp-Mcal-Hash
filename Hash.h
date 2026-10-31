/**
 * \author Mr.Nobody
 * \file Hash.h
 * \ingroup Hash
 * \brief Hash module common functionality header file.
 *
 * This file contains the common functionality used internally by the module,
 * and shall provide interface between the module and the application.
 *
 */

#ifndef HASH_HASH_H
#define HASH_HASH_H

#ifdef __cplusplus
extern "C" {
#endif

/* ============================= INCLUDES =================================== */
#include "Hash_Types.h"            /* Module types definitions       */
/* ============================= TYPEDEFS =================================== */

/** \brief Properties of one algorithm needed to drive the hardware, indexed by
 *  \ref hash_Algorithm_t */
typedef struct
{
    hash_FunctionState_t Supported;   /**< Algorithm is implemented by the device (\ref Hash_Get_Capability) */
    uint32_t             AlgoCrValue; /**< HASH_CR.ALGO[3:0] value, already positioned                       */
    hash_DataCnt_t       BlockSize;   /**< Input block size in bytes (HMAC key block comparison, LKEY)       */
    hash_DataCnt_t       DigestSize;  /**< Digest size in bytes, 0 for the extendable output functions       */
}   hash_AlgoProps_t;


/** \brief Count of header words (HASH_IMR, HASH_STR, HASH_CR and the module's incomplete word with its
 *  byte count) saved ahead of the context swap registers in \ref hash_ContextLayout_t */
#define HASH_CONTEXT_HEADER_WORDS      ( 5u )

/** \brief Layout of the opaque \ref hash_Context_t storage (HASH suspend/resume
 *  registers, see RM0481/RM0492/RM0517 HASH chapter, suspend/resume operations) */
typedef struct
{
    uint32_t Imr;                                                                           /**< Saved HASH_IMR    */
    uint32_t Str;                                                                           /**< Saved HASH_STR    */
    uint32_t Cr;                                                                            /**< Saved HASH_CR     */
    uint32_t PendingWord;                                                                   /**< Incomplete word  */
    uint32_t PendingCnt;                                                                    /**< Bytes of the word */
    uint32_t Csr[ ( HASH_CONTEXT_SIZE / sizeof( uint32_t ) ) - HASH_CONTEXT_HEADER_WORDS ]; /**< Saved HASH_CSR0.. */
}   hash_ContextLayout_t;

_Static_assert( sizeof( hash_ContextLayout_t ) <= HASH_CONTEXT_SIZE,
                "Hash: hash_ContextLayout_t does not fit hash_Context_t." );

/* ========================= SYMBOLIC CONSTANTS ============================= */

/* ========================= EXPORTED MACROS ================================ */

/* ========================= EXPORTED VARIABLES ============================= */

/* ======================== EXPORTED FUNCTIONS ============================== */

#ifdef __cplusplus
}
#endif

#endif /* HASH_HASH_H */
