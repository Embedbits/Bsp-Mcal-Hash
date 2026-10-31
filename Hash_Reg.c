/**
 * \author Mr.Nobody
 * \file Hash_Reg.c
 * \ingroup Hash
 * \brief Hash module Reg component functionality.
 *
 * Register access of the module: generic accessors (bounds checked register ID),
 * the indexed context swap / digest registers and the suspend / resume sequence
 * of RM0481, RM0492, RM0517 (HASH chapter, suspend / resume operations). The
 * registers are written only here, the masks come from the CMSIS device header.
 *
 * HASH_HR0 .. HASH_HR41 (the full digest, used for SHA2-384/512 and SHA-3) are
 * not part of the CMSIS HASH_TypeDef (only the aliased HASH_HRA0 .. HASH_HRA4
 * are, at offset 0x0C), they are accessed at their fixed offset 0x310 instead.
 *
 */
/* ============================== INCLUDES ================================== */
#include "Hash_Reg.h"                       /* Self include                   */
#include "Hash_Types.h"                     /* Module types definitions       */
#include "Stm32.h"                          /* HASH registers definition      */
/* ============================== TYPEDEFS ================================== */

/** \brief Structure type used to store physical address of HASH registers.
 * This array is used to reduce size of configuration array. With this style
 * the registers are referenced through enumeration.
 *
 */
typedef struct
{
    hash_RegId_t        RegId;   /**< Peripheral register ID      */
    volatile uint32_t * RegAddr; /**< Peripheral register address */
}   hash_RegList_t;

/* ======================== FORWARD DECLARATIONS ============================ */

/* ========================== SYMBOLIC CONSTANTS ============================ */

/** \brief Register value without any bit set (masked register value of an inactive bit field) */
#define HASH_REG_BITS_CLEAR              ( 0u )

/** \brief Count of read-back iterations of a written register value */
#define HASH_REG_READBACK_TIMEOUT_RAW    ( 0x1000u )

/** \brief Byte offset of HASH_HR0 (the full digest register bank) from the HASH base address */
#define HASH_REG_HR_BASE_OFFSET          ( 0x310u )

/** \brief Size in bytes of one HASH register */
#define HASH_REG_WORD_SIZE               ( 4u )

/* =============================== MACROS =================================== */

/* ========================== EXPORTED VARIABLES ============================ */

/* =========================== LOCAL VARIABLES ============================== */

/** \brief HASH registers configuration structure
 *
 * This structure is used to store addresses of HASH registers.
 * It is used to reduce code size while referring to HASH registers.
 */
static const hash_RegList_t             hash_RegList[] =
{
    { .RegId = HASH_REG_CR  , .RegAddr = &(HASH->CR ) }, /**< HASH control register          */
    { .RegId = HASH_REG_DIN , .RegAddr = &(HASH->DIN) }, /**< HASH data input register       */
    { .RegId = HASH_REG_STR , .RegAddr = &(HASH->STR) }, /**< HASH start register            */
    { .RegId = HASH_REG_IMR , .RegAddr = &(HASH->IMR) }, /**< HASH interrupt enable register */
    { .RegId = HASH_REG_SR  , .RegAddr = &(HASH->SR ) }, /**< HASH status register           */
};

_Static_assert( (sizeof(hash_RegList) / sizeof(hash_RegList_t)) == HASH_REG_CNT,
                "Hash_Reg: hash_RegList has incorrect size." );

/* ========================= EXPORTED FUNCTIONS ============================= */

/**
 * \brief Sets the register bit with given mask.
 *
 * \param regId   [in]: HASH register ID
 * \param bitMask [in]: Mask to apply to the register
 */
void Hash_Set_RegBit( hash_RegId_t regId, uint32_t bitMask )
{
    if( HASH_REG_CNT > regId )
    {
        *hash_RegList[regId].RegAddr |= bitMask;
    }
    else
    {
        /* Invalid register ID, no action required */
    }
}


/**
 * \brief Resets the register bit with given mask.
 *
 * \param regId   [in]: HASH register ID
 * \param bitMask [in]: Mask to apply to the register
 */
void Hash_Reset_RegBit( hash_RegId_t regId, uint32_t bitMask )
{
    if( HASH_REG_CNT > regId )
    {
        *hash_RegList[regId].RegAddr &= ~bitMask;
    }
    else
    {
        /* Invalid register ID, no action required */
    }
}


/**
 * \brief Gets the register bit value with given mask.
 *
 * \param regId   [in]: HASH register ID
 * \param bitMask [in]: Mask to apply to the register
 * \return Register bit value with applied mask, no bit set for invalid register ID
 */
uint32_t Hash_Get_RegBit( hash_RegId_t regId, uint32_t bitMask )
{
    uint32_t retValue = HASH_REG_BITS_CLEAR;

    if( HASH_REG_CNT > regId )
    {
        retValue = ( *hash_RegList[regId].RegAddr & bitMask );
    }
    else
    {
        /* Invalid register ID, no bit is set */
        retValue = HASH_REG_BITS_CLEAR;
    }

    return ( retValue );
}


/**
 * \brief Updates the register value with given mask and value.
 *
 * \param regId    [in]: HASH register ID
 * \param regMask  [in]: Mask to apply to the register
 * \param regValue [in]: Value to set in the register
 */
void Hash_Set_RegVal( hash_RegId_t regId, uint32_t regMask, uint32_t regValue )
{
    if( HASH_REG_CNT > regId )
    {
        *hash_RegList[regId].RegAddr = ( ( *hash_RegList[regId].RegAddr & ~regMask ) |
                                         ( regValue & regMask ) );
    }
    else
    {
        /* Invalid register ID, no action required */
    }
}


/**
 * \brief Gets the register value with given mask.
 *
 * \param regId   [in]: HASH register ID
 * \param regMask [in]: Mask to apply to the register
 * \return Register value with applied mask, no bit set for invalid register ID
 */
uint32_t Hash_Get_RegVal( hash_RegId_t regId, uint32_t regMask )
{
    uint32_t retValue = HASH_REG_BITS_CLEAR;

    if( HASH_REG_CNT > regId )
    {
        retValue = ( *hash_RegList[regId].RegAddr & regMask );
    }
    else
    {
        /* Invalid register ID, no bit is set */
        retValue = HASH_REG_BITS_CLEAR;
    }

    return ( retValue );
}


/**
 * \brief Waits until the register (bit field) reads back the required value.
 *
 * \param regId    [in]: HASH register ID
 * \param regMask  [in]: Mask of the checked bits
 * \param regValue [in]: Required value of the masked bits
 *
 * \return Returns \ref HASH_REQUEST_OK if the value was read back within the
 *         timeout. Otherwise returns \ref HASH_REQUEST_ERROR.
 */
hash_RequestState_t Hash_Reg_Wait_RegVal( hash_RegId_t regId, uint32_t regMask, uint32_t regValue )
{
    hash_RequestState_t retState = HASH_REQUEST_ERROR;

    for( uint32_t iterationCnt = 0u; HASH_REG_READBACK_TIMEOUT_RAW > iterationCnt; iterationCnt ++ )
    {
        const uint32_t actualValue = Hash_Get_RegVal( regId, regMask );

        if( ( regValue & regMask ) == actualValue )
        {
            retState = HASH_REQUEST_OK;
            break;
        }
        else
        {
            /* Register has not been updated yet */
            retState = HASH_REQUEST_ERROR;
        }
    }

    return ( retState );
}


/**
 * \brief Returns the address of HASH_DIN as a plain 32-bit value, for the Gpdma
 *        destination address of the DMA transfer mode (\ref Hash_Calc_OneShot_Dma).
 *
 * \return Address of HASH_DIN.
 */
uint32_t Hash_Reg_Get_DinAddr( void )
{
    return ( (uint32_t)(uintptr_t)hash_RegList[ HASH_REG_DIN ].RegAddr );
}


/**
 * \brief Writes one HASH context swap register (HASH_CSRx).
 *
 * \param csrIdx [in]: Index of the register (0 .. \ref HASH_REG_CSR_CNT - 1)
 * \param value  [in]: Value to write
 */
void Hash_Reg_Set_CsrWord( uint32_t csrIdx, uint32_t value )
{
    if( HASH_REG_CSR_CNT > csrIdx )
    {
        HASH->CSR[ csrIdx ] = value;
    }
    else
    {
        /* Invalid index, no action required */
    }
}


/**
 * \brief Reads one HASH context swap register (HASH_CSRx).
 *
 * \param csrIdx [in]: Index of the register (0 .. \ref HASH_REG_CSR_CNT - 1)
 * \return Register value, 0 for an invalid index
 */
uint32_t Hash_Reg_Get_CsrWord( uint32_t csrIdx )
{
    uint32_t retValue = HASH_REG_BITS_CLEAR;

    if( HASH_REG_CSR_CNT > csrIdx )
    {
        retValue = HASH->CSR[ csrIdx ];
    }
    else
    {
        /* Invalid index, no bit is set */
        retValue = HASH_REG_BITS_CLEAR;
    }

    return ( retValue );
}


/**
 * \brief Reads one digest register (HASH_HRx, the full digest at offset 0x310).
 *
 * \note  HASH_HR0 .. HASH_HR4 are the same storage as the aliased HASH_HRA0 ..
 *        HASH_HRA4 (RM0481/RM0492/RM0517, HASH digest registers), reading them
 *        at the 0x310 offset also works for SHA-1 (the only algorithm every
 *        line supports).
 *
 * \param hrIdx [in]: Index of the register (0 .. \ref HASH_REG_HR_CNT - 1)
 * \return Register value, 0 for an invalid index
 */
uint32_t Hash_Reg_Get_DigestWord( uint32_t hrIdx )
{
    uint32_t retValue = HASH_REG_BITS_CLEAR;

    if( HASH_REG_HR_CNT > hrIdx )
    {
        const uint8_t    *hashBase = (const uint8_t *)HASH;
        const uint32_t     byteOff = ( HASH_REG_HR_BASE_OFFSET + ( HASH_REG_WORD_SIZE * hrIdx ) );
        const volatile uint32_t *hrAddr = (const volatile uint32_t *)( hashBase + byteOff );

        retValue = *hrAddr;
    }
    else
    {
        /* Invalid index, no bit is set */
        retValue = HASH_REG_BITS_CLEAR;
    }

    return ( retValue );
}


/**
 * \brief Saves the suspend / resume context from the registers to memory.
 *
 * Reads HASH_IMR, HASH_STR, HASH_CR and the leading \p csrCnt context swap
 * registers (RM0481/RM0492/RM0517, HASH suspend/resume operations: the number
 * of relevant HASH_CSRx registers depends on the algorithm and on whether an
 * HMAC operation was ongoing, the caller already calculated it).
 *
 * \param context [out]: Destination of the saved registers
 * \param csrCnt  [in]:  Number of context swap registers to save (0 .. \ref HASH_REG_CSR_CNT)
 */
void Hash_Reg_Save_Context( hash_ContextLayout_t * const context, uint32_t csrCnt )
{
    if( HASH_NULL_PTR != context )
    {
        uint32_t boundedCnt = HASH_REG_CSR_CNT;

        if( HASH_REG_CSR_CNT > csrCnt )
        {
            boundedCnt = csrCnt;
        }
        else
        {
            /* Count already clamped to HASH_REG_CSR_CNT */
        }

        context->Imr = Hash_Get_RegVal( HASH_REG_IMR, HASH_REG_FULL_MASK );
        context->Str = Hash_Get_RegVal( HASH_REG_STR, HASH_REG_FULL_MASK );
        context->Cr  = Hash_Get_RegVal( HASH_REG_CR , HASH_REG_FULL_MASK );

        for( uint32_t csrIdx = 0u; boundedCnt > csrIdx; csrIdx++ )
        {
            context->Csr[ csrIdx ] = Hash_Reg_Get_CsrWord( csrIdx );
        }
    }
    else
    {
        /* Invalid pointer, no action required */
    }
}


/**
 * \brief Restores the suspend / resume context from memory to the registers.
 *
 * Follows the resume sequence of RM0481/RM0492/RM0517 (HASH suspend/resume
 * operations): HASH_IMR, HASH_STR and HASH_CR are written first, then the
 * HASH core is initialized (HASH_CR.INIT), and only then the context swap
 * registers are written back.
 *
 * \param context [in]: Source of the registers to restore
 * \param csrCnt  [in]: Number of context swap registers to restore (0 .. \ref HASH_REG_CSR_CNT)
 */
void Hash_Reg_Restore_Context( const hash_ContextLayout_t * const context, uint32_t csrCnt )
{
    if( HASH_NULL_PTR != context )
    {
        uint32_t boundedCnt = HASH_REG_CSR_CNT;

        if( HASH_REG_CSR_CNT > csrCnt )
        {
            boundedCnt = csrCnt;
        }
        else
        {
            /* Count already clamped to HASH_REG_CSR_CNT */
        }

        Hash_Set_RegVal( HASH_REG_IMR, HASH_REG_FULL_MASK, context->Imr );
        Hash_Set_RegVal( HASH_REG_STR, HASH_REG_FULL_MASK, context->Str );
        Hash_Set_RegVal( HASH_REG_CR , HASH_REG_FULL_MASK, context->Cr  );

        Hash_Set_RegBit( HASH_REG_CR, HASH_CR_INIT );

        for( uint32_t csrIdx = 0u; boundedCnt > csrIdx; csrIdx++ )
        {
            Hash_Reg_Set_CsrWord( csrIdx, context->Csr[ csrIdx ] );
        }
    }
    else
    {
        /* Invalid pointer, no action required */
    }
}

/* =========================== LOCAL FUNCTIONS ============================== */

/* =========================== INTERRUPT HANDLERS =========================== */

/* ================================ TASKS =================================== */
