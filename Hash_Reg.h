/**
 * \author Mr.Nobody
 * \file Hash_Reg.h
 * \ingroup Hash
 * \brief Hash module Reg component header file.
 *
 * This component contains functionality for register operations. It is private
 * to the module (the register access is not shared with other modules).
 *
 */

#ifndef HASH_REG_HASH_REG_H
#define HASH_REG_HASH_REG_H

#ifdef __cplusplus
extern "C" {
#endif

/* ============================= INCLUDES =================================== */
#include "Hash.h"                           /* Module internal types          */
#include "Hash_Types.h"                     /* Module types definition        */
/* ============================= TYPEDEFS =================================== */

/** \brief List of HASH registers accessed as a single 32-bit value */
typedef enum
{
    HASH_REG_CR = 0u, /**< HASH control register             */
    HASH_REG_DIN,     /**< HASH data input register          */
    HASH_REG_STR,     /**< HASH start register               */
    HASH_REG_IMR,     /**< HASH interrupt enable register    */
    HASH_REG_SR,      /**< HASH status register              */
    HASH_REG_CNT      /**< Count of available HASH registers */
}   hash_RegId_t;

/* ========================= SYMBOLIC CONSTANTS ============================= */

/** \brief Count of context swap registers (HASH_CSR0 .. HASH_CSR102) */
#define HASH_REG_CSR_CNT                 ( 103u )

/** \brief Count of digest registers accessible through HASH_HRx (HR0 .. HR41) */
#define HASH_REG_HR_CNT                  ( 42u )

/** \brief Full register mask, used to write / read back a whole 32-bit register at once */
#define HASH_REG_FULL_MASK               ( 0xFFFFFFFFu )

/* ========================= EXPORTED MACROS ================================ */

/* ========================= EXPORTED VARIABLES ============================= */

/* ======================== EXPORTED FUNCTIONS ============================== */

/* ---------------------------- Generic accessors --------------------------- */

void                        Hash_Set_RegBit             ( hash_RegId_t regId, uint32_t bitMask );
void                        Hash_Reset_RegBit           ( hash_RegId_t regId, uint32_t bitMask );
uint32_t                    Hash_Get_RegBit             ( hash_RegId_t regId, uint32_t bitMask );

void                        Hash_Set_RegVal             ( hash_RegId_t regId, uint32_t regMask, uint32_t regValue );
uint32_t                    Hash_Get_RegVal             ( hash_RegId_t regId, uint32_t regMask );

hash_RequestState_t         Hash_Reg_Wait_RegVal        ( hash_RegId_t regId, uint32_t regMask, uint32_t regValue );

uint32_t                    Hash_Reg_Get_DinAddr        ( void );

/* ------------------------------ Indexed arrays ----------------------------- */

void                        Hash_Reg_Set_CsrWord        ( uint32_t csrIdx, uint32_t value );
uint32_t                    Hash_Reg_Get_CsrWord        ( uint32_t csrIdx );

uint32_t                    Hash_Reg_Get_DigestWord     ( uint32_t hrIdx );

/* -------------------------- Suspend / resume sequence ----------------------- */

void                        Hash_Reg_Save_Context       ( hash_ContextLayout_t * const context, uint32_t csrCnt );
void                        Hash_Reg_Restore_Context    ( const hash_ContextLayout_t * const context, uint32_t csrCnt );

#ifdef __cplusplus
}
#endif

#endif /* HASH_REG_HASH_REG_H */
