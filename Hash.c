/**
 * \author Mr.Nobody
 * \file Hash.c
 * \ingroup Hash
 * \brief Hash module common functionality
 *
 * # Introduction #
 * The hash processor (HASH) computes the message digest of a byte stream with
 * SHA-1, SHA-2 and (where the device has it) SHA-3, plain or keyed (HMAC). The
 * module packs arbitrary length / alignment byte input into the 32-bit words
 * the peripheral requires (HASH_CR.DATATYPE = byte swap, RM0481/RM0492/RM0517
 * HASH chapter, message data feeding), keeps the incomplete last word in its
 * own state and pads the message through HASH_STR.NBLW at the end.
 *
 * # Device differences (STM32H5) #
 * Verified against the CMSIS device headers and RM0481 Table 397 / block
 * diagrams of RM0492 and RM0517 (not from memory, see the card):
 * - SHA-1, SHA2-224, SHA2-256: all twelve lines (HASH_CR.ALGO is at least 2 bit
 *   wide everywhere).
 * - SHA2-384, SHA2-512, SHA2-512/224, SHA2-512/256: all lines except H503
 *   (HASH_CR.ALGO is only 2 bit wide on H503, these encodings need bit 19/20).
 * - SHA-3 family and SHAKE128/256: only H543, H553, H5E4, H5E5, H5F4, H5F5.
 *   RM0481 Table 397 explicitly lists SHA-3 as "-" for H523/533/562/563/573xx
 *   and "X" for H543/553xx; the H503 and H5E4../H5F5.. block diagrams confirm
 *   the same split (SHA-1, SHA-2 only vs. SHA-1, SHA-2, SHA-3). This is a finer
 *   split than the "H503 has SHA-1/224/256 only" note in the module card.
 * - MD5 is not implemented by the STM32H5 HASH IP (no HASH_CR.ALGO encoding).
 *
 * # Incremental interface #
 * \ref Hash_Set_Start opens a calculation and (for HMAC) writes the inner key.
 * \ref Hash_Set_Update buffers data in a 4 byte accumulator and pushes full
 * words to HASH_DIN; a calculation stays open across calls. \ref Hash_Set_Finish
 * pushes the remainder with HASH_STR.NBLW and DCAL, and for HMAC pushes the
 * (outer) key a second time (RM0481 HMAC operation, 4 step procedure).
 *
 * # Suspend and resume #
 * \ref Hash_Get_Context / \ref Hash_Set_Context follow the data-loaded-by-
 * software sequence of the suspend/resume operations section: save HASH_IMR,
 * HASH_STR, HASH_CR and HASH_CSR0 .. HASH_CSRx; resume writes IMR/STR/CR,
 * sets INIT, then writes the HASH_CSRx back. The module always saves the
 * HMAC-extended register count of the algorithm's group (conservative
 * superset of the exact count required by the RM, never fewer).
 *
 * # Transfer modes #
 * POLL and ISR cover one-shot, incremental, HMAC and suspend/resume. DMA
 * (\ref HASH_XFER_MODE_DMA) serves the plain one-shot request (\ref Hash_Set_Calculate,
 * \ref HASH_MODE_HASH; HMAC needs two more software driven key phases and is
 * rejected). The Gpdma channel is initialized by \ref Hash_Init. A request
 * programs HASH_STR.NBLW before the transfer starts and moves the message in
 * chunks (RM0481/RM0492/RM0517 HASH DMA interface): HASH_CR.MDMAT is set for
 * every chunk except the last one (chunk size a multiple of four words), the
 * HASH sets DCAL itself after the last chunk. The HASH clears HASH_CR.DMAE at
 * the end of every transfer (also with MDMAT set, observed on the H503), DMAE
 * is therefore set again for every chunk. The 0..15 trailing bytes are sent
 * from a word-aligned copy in the module, the DMA never reads past the end of
 * the message. The digest complete interrupt (enabled after the last chunk)
 * reads the digest into the request buffer and calls the completion callback.
 *
 */
/* ============================== INCLUDES ================================== */
#include "Hash.h"                           /* Self include                   */
#include "Hash_Port.h"                      /* Own port file include          */
#include "Hash_Types.h"                     /* Module types definitions       */
#include "Hash_Reg.h"                       /* Register access                */
#include "Nvic_Port.h"                      /* NVIC handler functionality     */
#include "Rcc_Port.h"                       /* RCC handler functionality      */
#include "Gpdma_Port.h"                     /* DMA handler functionality      */
#include "Stm32.h"                          /* HASH registers definition      */
/* ============================== TYPEDEFS ================================== */

/** \brief Count of bytes forming one HASH_DIN word (needed ahead of \ref hash_RuntimeData_t) */
#define HASH_WORD_SIZE                   ( 4u )

/** \brief Runtime data of the module */
typedef struct
{
    hash_FunctionState_t     InitState;                 /**< Hash_Init succeeded                                */
    hash_XferMode_t          XferMode;                  /**< Configured data transfer mode                      */
    gpdma_PeriphId_t         DmaPeriphId;               /**< Gpdma controller (DMA mode only)                   */
    gpdma_ChannelId_t        DmaChannelId;              /**< Gpdma channel (DMA mode only)                      */
    gpdma_Priority_t         DmaChannelPrio;            /**< Gpdma channel priority (DMA mode only)             */
    hash_CompleteCallback_t *CompleteCallback;          /**< User completion callback                           */
    hash_ErrorCallback_t    *ErrorCallback;             /**< User error callback                                */
    hash_State_t             State;                     /**< Request processing state                           */
    hash_XferError_t         XferError;                 /**< Last transfer error mask                           */
    hash_FunctionState_t     CalcOpen;                  /**< Incremental calculation opened by Hash_Set_Start   */
    hash_Algorithm_t         CurAlgorithm;              /**< Algorithm of the open calculation / DMA request    */
    hash_Mode_t              CurMode;                   /**< Hash / HMAC mode of the open calculation           */
    const hash_Data_t       *OuterKey;                  /**< HMAC outer key, written again by Hash_Set_Finish   */
    hash_DataCnt_t           OuterKeySize;              /**< HMAC outer key size in bytes                       */
    uint8_t                  Pending[ HASH_WORD_SIZE ]; /**< Bytes not yet forming a full 32-bit word           */
    uint8_t                  PendingCnt;                /**< Number of valid bytes in \ref Pending              */
    hash_FunctionState_t     AnyWordWritten;            /**< At least one word was written since the last INIT  */
    hash_FunctionState_t     DmaInit;                   /**< Gpdma channel initialized by Hash_Init (DMA mode)  */
    hash_Data_t             *Digest;                    /**< Digest buffer of the running DMA request           */
    hash_DataCnt_t           DigestSize;                /**< Size of \ref Digest in bytes                       */
    uint32_t                 DmaNextAddr;               /**< Message address of the next DMA chunk              */
    hash_DataCnt_t           DmaBodyLeft;               /**< Message bytes left for the next DMA chunks         */
    hash_DataCnt_t           DmaTailBytes;              /**< Trailing bytes waiting in the word-aligned copy    */
    hash_FunctionState_t     DmaLastChunk;              /**< The last DMA chunk of the message is running       */
}   hash_RuntimeData_t;

/* ======================== FORWARD DECLARATIONS ============================ */

static const hash_AlgoProps_t *Hash_Get_AlgoProps     ( hash_Algorithm_t algorithm );
static uint32_t                 Hash_Calc_CsrCount      ( hash_Algorithm_t algorithm );

static hash_RequestState_t      Hash_Reg_Open_Calc   ( hash_Algorithm_t algorithm,
                                                       hash_Mode_t mode,
                                                       const hash_Data_t * const key,
                                                       hash_DataCnt_t keySize );
static void                     Hash_Push_Bytes          ( const hash_Data_t * const data, hash_DataCnt_t dataSize );
static void                     Hash_Push_Word           ( uint32_t word );
static hash_RequestState_t      Hash_Push_Final           ( void );
static hash_RequestState_t      Hash_Wait_DataInReady     ( void );
static hash_RequestState_t      Hash_Wait_DigestReady     ( void );
static void                     Hash_Read_Digest           ( hash_Data_t * const digest, hash_DataCnt_t digestSize );

static hash_RequestState_t      Hash_Calc_OneShot_Poll    ( const hash_Request_t * const request );
static hash_RequestState_t      Hash_Calc_OneShot_Dma     ( const hash_Request_t * const request );

static hash_RequestState_t      Hash_Init_Dma              ( const hash_Config_t * const hashConfig );
static hash_RequestState_t      Hash_Release_Dma           ( void );
static void                     Hash_Fill_DmaTail          ( const hash_Data_t * const data, hash_DataCnt_t dataSize );
static hash_RequestState_t      Hash_Start_DmaChunk        ( void );
static void                     Hash_Stop_DmaHw            ( void );

static void                     Hash_IsrHandler            ( void );
static void                     Hash_DmaCompleteIsr         ( void );
static void                     Hash_DmaErrorIsr            ( gpdma_ErrorMaskId_t errMask );

/* ========================== SYMBOLIC CONSTANTS ============================ */

/** Value of major version of SW module */
#define HASH_MAJOR_VERSION               ( 0u )

/** Value of minor version of SW module */
#define HASH_MINOR_VERSION               ( 1u )

/** Value of patch version of SW module */
#define HASH_PATCH_VERSION               ( 0u )

/** Default interrupt priority used by \ref Hash_Get_DefaultConfig */
#define HASH_DEFAULT_IRQ_PRIO            ( 0u )

/** Count of bits in one byte */
#define HASH_BITS_PER_BYTE               ( 8u )

/** Count of bits in one HASH_DIN word */
#define HASH_BITS_PER_WORD                ( 32u )

/** Value of HASH_STR.NBLW meaning "all 32 bits of the last word are valid" */
#define HASH_NBLW_ALL_VALID               ( 0u )

/** Count of read-back / ready-wait iterations (no interrupt, no DMA) */
#define HASH_POLL_TIMEOUT_RAW             ( 0x400000u )

/** Mask of the address bits that must be zero for a word-aligned DMA source */
#define HASH_WORD_ALIGN_MASK              ( HASH_WORD_SIZE - 1u )

/** Size granularity of a DMA chunk with HASH_CR.MDMAT set: four words (RM0481/RM0492/RM0517 HASH DMA interface) */
#define HASH_DMA_CHUNK_ALIGN              ( 16u )

/** Largest DMA chunk: the biggest multiple of \ref HASH_DMA_CHUNK_ALIGN within the 16-bit Gpdma block size */
#define HASH_DMA_CHUNK_MAX                ( 65520u )

/** Count of words of the trailing bytes copy (0..15 bytes, see \ref HASH_DMA_CHUNK_ALIGN) */
#define HASH_DMA_TAIL_WORDS               ( HASH_DMA_CHUNK_ALIGN / HASH_WORD_SIZE )

/** Gpdma errors reported by the DMA mode. The suspension is left out: Hash_Set_Abort() stops the channel by
 *  Gpdma_Set_ChannelInactive(), which polls the suspension flag itself */
#define HASH_DMA_ERROR_MASK               ( GPDMA_ERROR_TRANSFER      | \
                                            GPDMA_ERROR_CONFIG_UPDATE | \
                                            GPDMA_ERROR_CONFIG_ERROR  | \
                                            GPDMA_ERROR_TRIG_OVERRUN )

/** Context swap register count, group of the 512-bit block algorithms (SHA-1, SHA2-224, SHA2-256),
 *  HMAC-extended (conservative superset, RM0481/RM0492/RM0517 suspend/resume operations) */
#define HASH_CSR_CNT_GROUP_SHORT          ( 54u )

/** Context swap register count, group of the 1024-bit block algorithms (SHA2-384/512, truncated or not),
 *  HMAC-extended (conservative superset) */
#define HASH_CSR_CNT_GROUP_LONG           ( 103u )

/** Context swap register count, SHA-3 / SHAKE group, HMAC-extended (conservative superset) */
#define HASH_CSR_CNT_GROUP_SHA3           ( 88u )

/** HASH_CR.ALGO encodings, RM0481/RM0492/RM0517 HASH control register (positioned bit values).
 *  HASH_CR_ALGO_2 / HASH_CR_ALGO_3 do not exist in the CMSIS header of the lines where
 *  HASH_CR.ALGO is only 2 bit wide (H503): the encodings that need them are then defined
 *  as \ref HASH_ALGO_CR_NONE, which is never written (\ref HASH_SUPPORT_SHA2_LONG and
 *  \ref HASH_SUPPORT_SHA3 reject the request before \ref Hash_Reg_Open_Calc). */
#define HASH_ALGO_CR_SHA1                 ( 0u )
#define HASH_ALGO_CR_SHA2_224             ( HASH_CR_ALGO_1 )
#define HASH_ALGO_CR_SHA2_256             ( HASH_CR_ALGO_1 | HASH_CR_ALGO_0 )
#define HASH_ALGO_CR_NONE                 ( 0u )

#if defined( HASH_CR_ALGO_2 ) && \
    defined( HASH_CR_ALGO_3 )
#define HASH_ALGO_CR_SHA2_384             ( HASH_CR_ALGO_3 | HASH_CR_ALGO_2 )
#define HASH_ALGO_CR_SHA2_512_224         ( HASH_CR_ALGO_3 | HASH_CR_ALGO_2 | HASH_CR_ALGO_0 )
#define HASH_ALGO_CR_SHA2_512_256         ( HASH_CR_ALGO_3 | HASH_CR_ALGO_2 | HASH_CR_ALGO_1 )
#define HASH_ALGO_CR_SHA2_512             ( HASH_CR_ALGO_3 | HASH_CR_ALGO_2 | HASH_CR_ALGO_1 | HASH_CR_ALGO_0 )
#define HASH_ALGO_CR_SHA3_224             ( HASH_CR_ALGO_2 )
#define HASH_ALGO_CR_SHA3_256             ( HASH_CR_ALGO_2 | HASH_CR_ALGO_0 )
#define HASH_ALGO_CR_SHA3_384             ( HASH_CR_ALGO_2 | HASH_CR_ALGO_1 )
#define HASH_ALGO_CR_SHA3_512             ( HASH_CR_ALGO_2 | HASH_CR_ALGO_1 | HASH_CR_ALGO_0 )
#define HASH_ALGO_CR_SHAKE128             ( HASH_CR_ALGO_3 )
#define HASH_ALGO_CR_SHAKE256             ( HASH_CR_ALGO_3 | HASH_CR_ALGO_0 )
#else
#define HASH_ALGO_CR_SHA2_384             ( HASH_ALGO_CR_NONE )
#define HASH_ALGO_CR_SHA2_512_224         ( HASH_ALGO_CR_NONE )
#define HASH_ALGO_CR_SHA2_512_256         ( HASH_ALGO_CR_NONE )
#define HASH_ALGO_CR_SHA2_512             ( HASH_ALGO_CR_NONE )
#define HASH_ALGO_CR_SHA3_224             ( HASH_ALGO_CR_NONE )
#define HASH_ALGO_CR_SHA3_256             ( HASH_ALGO_CR_NONE )
#define HASH_ALGO_CR_SHA3_384             ( HASH_ALGO_CR_NONE )
#define HASH_ALGO_CR_SHA3_512             ( HASH_ALGO_CR_NONE )
#define HASH_ALGO_CR_SHAKE128             ( HASH_ALGO_CR_NONE )
#define HASH_ALGO_CR_SHAKE256             ( HASH_ALGO_CR_NONE )
#endif /* HASH_CR_ALGO_2 && HASH_CR_ALGO_3 */

/** Block size in bytes, 512-bit block algorithms */
#define HASH_BLOCK_SIZE_SHORT              ( 64u )

/** Block size in bytes, 1024-bit block algorithms */
#define HASH_BLOCK_SIZE_LONG               ( 128u )

/** Digest size in bytes */
#define HASH_DIGEST_SIZE_SHA1               ( 20u )
#define HASH_DIGEST_SIZE_224                ( 28u )
#define HASH_DIGEST_SIZE_256                ( 32u )
#define HASH_DIGEST_SIZE_384                ( 48u )
#define HASH_DIGEST_SIZE_512                ( 64u )
#define HASH_DIGEST_SIZE_VARIABLE            ( 0u )

/** Block size in bytes, SHA-3 / SHAKE family (RM0481/RM0492/RM0517 information on supported algorithms) */
#define HASH_BLOCK_SIZE_SHA3_224              ( 144u )
#define HASH_BLOCK_SIZE_SHA3_256              ( 136u )
#define HASH_BLOCK_SIZE_SHA3_384              ( 104u )
#define HASH_BLOCK_SIZE_SHA3_512              ( 72u )
#define HASH_BLOCK_SIZE_SHAKE128              ( 168u )
#define HASH_BLOCK_SIZE_SHAKE256              ( 136u )

/** Device line implements the 1024-bit block algorithms (all lines except H503, confirmed through the
 *  CMSIS HASH_CR_ALGO_Msk width: 2 bit on H503, 4 bit elsewhere) */
#if defined( STM32H503xx )
#define HASH_SUPPORT_SHA2_LONG              ( HASH_FUNCTION_INACTIVE )
#else
#define HASH_SUPPORT_SHA2_LONG              ( HASH_FUNCTION_ACTIVE )
#endif /* STM32H503xx */

/** Device line implements SHA-3 / SHAKE (RM0481 Table 397 and RM0492 / RM0517 block diagrams) */
#if defined( STM32H543xx ) || \
    defined( STM32H553xx ) || \
    defined( STM32H5E4xx ) || \
    defined( STM32H5E5xx ) || \
    defined( STM32H5F4xx ) || \
    defined( STM32H5F5xx )
#define HASH_SUPPORT_SHA3                    ( HASH_FUNCTION_ACTIVE )
#else
#define HASH_SUPPORT_SHA3                    ( HASH_FUNCTION_INACTIVE )
#endif /* SHA-3 lines */

/* =============================== MACROS =================================== */

/* ========================== EXPORTED VARIABLES ============================ */

/* =========================== LOCAL VARIABLES ============================== */

/** \brief Algorithm properties, indexed by \ref hash_Algorithm_t */
static const hash_AlgoProps_t hash_AlgoLut[ HASH_ALGO_CNT ] =
{
    /* HASH_ALGO_MD5          */
    { .Supported = HASH_FUNCTION_INACTIVE, .AlgoCrValue = HASH_ALGO_CR_NONE,
      .BlockSize  = HASH_BLOCK_SIZE_SHORT, .DigestSize  = HASH_DIGEST_SIZE_224 },
    /* HASH_ALGO_SHA1         */
    { .Supported = HASH_FUNCTION_ACTIVE,   .AlgoCrValue = HASH_ALGO_CR_SHA1,
      .BlockSize  = HASH_BLOCK_SIZE_SHORT, .DigestSize  = HASH_DIGEST_SIZE_SHA1 },
    /* HASH_ALGO_SHA2_224     */
    { .Supported = HASH_FUNCTION_ACTIVE,   .AlgoCrValue = HASH_ALGO_CR_SHA2_224,
      .BlockSize  = HASH_BLOCK_SIZE_SHORT, .DigestSize  = HASH_DIGEST_SIZE_224 },
    /* HASH_ALGO_SHA2_256     */
    { .Supported = HASH_FUNCTION_ACTIVE,   .AlgoCrValue = HASH_ALGO_CR_SHA2_256,
      .BlockSize  = HASH_BLOCK_SIZE_SHORT, .DigestSize  = HASH_DIGEST_SIZE_256 },
    /* HASH_ALGO_SHA2_384     */
    { .Supported = HASH_SUPPORT_SHA2_LONG, .AlgoCrValue = HASH_ALGO_CR_SHA2_384,
      .BlockSize  = HASH_BLOCK_SIZE_LONG,  .DigestSize  = HASH_DIGEST_SIZE_384 },
    /* HASH_ALGO_SHA2_512     */
    { .Supported = HASH_SUPPORT_SHA2_LONG, .AlgoCrValue = HASH_ALGO_CR_SHA2_512,
      .BlockSize  = HASH_BLOCK_SIZE_LONG,  .DigestSize  = HASH_DIGEST_SIZE_512 },
    /* HASH_ALGO_SHA2_512_224 */
    { .Supported = HASH_SUPPORT_SHA2_LONG, .AlgoCrValue = HASH_ALGO_CR_SHA2_512_224,
      .BlockSize  = HASH_BLOCK_SIZE_LONG,  .DigestSize  = HASH_DIGEST_SIZE_224 },
    /* HASH_ALGO_SHA2_512_256 */
    { .Supported = HASH_SUPPORT_SHA2_LONG, .AlgoCrValue = HASH_ALGO_CR_SHA2_512_256,
      .BlockSize  = HASH_BLOCK_SIZE_LONG,  .DigestSize  = HASH_DIGEST_SIZE_256 },
    /* HASH_ALGO_SHA3_224     */
    { .Supported = HASH_SUPPORT_SHA3,      .AlgoCrValue = HASH_ALGO_CR_SHA3_224,
      .BlockSize  = HASH_BLOCK_SIZE_SHA3_224,                  .DigestSize  = HASH_DIGEST_SIZE_224 },
    /* HASH_ALGO_SHA3_256     */
    { .Supported = HASH_SUPPORT_SHA3,      .AlgoCrValue = HASH_ALGO_CR_SHA3_256,
      .BlockSize  = HASH_BLOCK_SIZE_SHA3_256,                  .DigestSize  = HASH_DIGEST_SIZE_256 },
    /* HASH_ALGO_SHA3_384     */
    { .Supported = HASH_SUPPORT_SHA3,      .AlgoCrValue = HASH_ALGO_CR_SHA3_384,
      .BlockSize  = HASH_BLOCK_SIZE_SHA3_384,                  .DigestSize  = HASH_DIGEST_SIZE_384 },
    /* HASH_ALGO_SHA3_512     */
    { .Supported = HASH_SUPPORT_SHA3,      .AlgoCrValue = HASH_ALGO_CR_SHA3_512,
      .BlockSize  = HASH_BLOCK_SIZE_SHA3_512,                   .DigestSize  = HASH_DIGEST_SIZE_512 },
    /* HASH_ALGO_SHAKE128     */
    { .Supported = HASH_SUPPORT_SHA3,      .AlgoCrValue = HASH_ALGO_CR_SHAKE128,
      .BlockSize  = HASH_BLOCK_SIZE_SHAKE128,                  .DigestSize  = HASH_DIGEST_SIZE_VARIABLE },
    /* HASH_ALGO_SHAKE256     */
    { .Supported = HASH_SUPPORT_SHA3,      .AlgoCrValue = HASH_ALGO_CR_SHAKE256,
      .BlockSize  = HASH_BLOCK_SIZE_SHAKE256,                  .DigestSize  = HASH_DIGEST_SIZE_VARIABLE },
};

/** \brief Runtime data of the module */
static volatile hash_RuntimeData_t hash_RuntimeData =
{
    .InitState        = HASH_FUNCTION_INACTIVE,
    .XferMode          = HASH_XFER_MODE_POLL,
    .DmaPeriphId       = GPDMA_PERIPH_1,
    .DmaChannelId      = GPDMA_CHANNEL_0,
    .DmaChannelPrio    = GPDMA_PRIORITY_LOW,
    .CompleteCallback  = HASH_NULL_PTR,
    .ErrorCallback      = HASH_NULL_PTR,
    .State              = HASH_STATE_IDLE,
    .XferError          = HASH_XFER_ERROR_NONE,
    .CalcOpen        = HASH_FUNCTION_INACTIVE,
    .CurAlgorithm       = HASH_ALGO_SHA1,
    .CurMode            = HASH_MODE_HASH,
    .OuterKey           = HASH_NULL_PTR,
    .OuterKeySize       = 0u,
    .Pending            = { 0u, 0u, 0u, 0u },
    .PendingCnt         = 0u,
    .AnyWordWritten     = HASH_FUNCTION_INACTIVE,
    .DmaInit            = HASH_FUNCTION_INACTIVE,
    .Digest             = HASH_NULL_PTR,
    .DigestSize         = 0u,
    .DmaNextAddr        = 0u,
    .DmaBodyLeft        = 0u,
    .DmaTailBytes       = 0u,
    .DmaLastChunk       = HASH_FUNCTION_INACTIVE,
};

/** \brief Static Gpdma transfer list storage of the DMA mode (must be static, Gpdma requirement) */
static volatile gpdma_XferList_t hash_DmaXferList[ 1 ];

/** \brief Word-aligned copy of the 0..15 trailing bytes of a DMA request, sent as the last chunk */
static volatile uint32_t hash_DmaTail[ HASH_DMA_TAIL_WORDS ];

/* ========================= EXPORTED FUNCTIONS ============================= */

/**
 * \brief Returns module SW version
 *
 * \return Module SW version
 */
hash_ModuleVersion_t Hash_Get_ModuleVersion( void )
{
    hash_ModuleVersion_t retVersion;

    retVersion.Major = HASH_MAJOR_VERSION;
    retVersion.Minor = HASH_MINOR_VERSION;
    retVersion.Patch = HASH_PATCH_VERSION;

    return ( retVersion );
}


/**
 * \brief Fills configuration structure with default values.
 *
 * Default configuration: POLL transfer mode, Gpdma1 channel 0 at low priority
 * (DMA mode only), interrupt priority 0, no callback.
 *
 * \param hashConfig [out]: Pointer to store default configuration. Must not be NULL.
 *
 * \return Function processing state. Returns \ref HASH_REQUEST_OK if request
 *         was processed without problems. Otherwise returns \ref HASH_REQUEST_ERROR.
 */
hash_RequestState_t Hash_Get_DefaultConfig( hash_Config_t * const hashConfig )
{
    hash_RequestState_t retState = HASH_REQUEST_ERROR;

    if( HASH_NULL_PTR != hashConfig )
    {
        hashConfig->XferMode          = HASH_XFER_MODE_POLL;
        hashConfig->DmaPeriphId        = GPDMA_PERIPH_1;
        hashConfig->DmaChannelId       = GPDMA_CHANNEL_0;
        hashConfig->DmaChannelPrio     = GPDMA_PRIORITY_LOW;
        hashConfig->IrqPriority        = HASH_DEFAULT_IRQ_PRIO;
        hashConfig->CompleteCallback   = HASH_NULL_PTR;
        hashConfig->ErrorCallback      = HASH_NULL_PTR;

        retState = HASH_REQUEST_OK;
    }
    else
    {
        retState = HASH_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Initializes the Hash module.
 *
 * Enables the peripheral clock (Rcc), resets the hardware state (runtime data
 * only - the hash core itself is initialized at the start of every request)
 * and, for \ref HASH_XFER_MODE_ISR / \ref HASH_XFER_MODE_DMA, configures the
 * HASH interrupt (Nvic) and activates HASH_IMR accordingly. In
 * \ref HASH_XFER_MODE_DMA the Gpdma channel of \p hashConfig is initialized and
 * its interrupt activated; a channel of an earlier DMA mode initialization is
 * released first.
 *
 * \pre   \p hashConfig shall not be \ref HASH_NULL_PTR and \ref hash_Config_t::XferMode
 *        shall be a valid value; otherwise \ref HASH_REQUEST_ERROR and nothing changes.
 *
 * \param hashConfig [in]: Pointer to Hash configuration, see \ref hash_Config_t. Must not be NULL.
 *
 * \return Function processing state. Returns \ref HASH_REQUEST_OK if request
 *         was processed without problems. Otherwise returns \ref HASH_REQUEST_ERROR.
 */
hash_RequestState_t Hash_Init( const hash_Config_t * const hashConfig )
{
    hash_RequestState_t retState = HASH_REQUEST_ERROR;

    if( ( HASH_NULL_PTR      != hashConfig           ) &&
        ( HASH_XFER_MODE_CNT >  hashConfig->XferMode )    )
    {
        const rcc_RequestState_t rccState = Rcc_Set_PeriphActive( RCC_PERIPH_HASH );

        if( RCC_REQUEST_OK == rccState )
        {
            retState = Hash_Release_Dma();

            if( ( HASH_REQUEST_OK     == retState             ) &&
                ( HASH_XFER_MODE_POLL != hashConfig->XferMode )    )
            {
                nvic_RequestState_t nvicState = Nvic_Set_PeriphIrq_Handler( NVIC_PERIPH_IRQ_HASH, Hash_IsrHandler );

                if( NVIC_REQUEST_OK == nvicState )
                {
                    nvicState = Nvic_Set_PeriphIrq_Prio( NVIC_PERIPH_IRQ_HASH, hashConfig->IrqPriority );
                }
                else
                {
                    /* Handler registration already failed */
                }

                if( NVIC_REQUEST_OK == nvicState )
                {
                    nvicState = Nvic_Set_PeriphIrq_Active( NVIC_PERIPH_IRQ_HASH );
                }
                else
                {
                    /* Priority configuration already failed */
                }

                if( NVIC_REQUEST_OK == nvicState )
                {
                    retState = HASH_REQUEST_OK;
                }
                else
                {
                    retState = HASH_REQUEST_ERROR;
                }
            }
            else
            {
                /* POLL mode does not use the interrupt, or the earlier Gpdma channel was not released */
            }

            if( ( HASH_REQUEST_OK    == retState             ) &&
                ( HASH_XFER_MODE_DMA == hashConfig->XferMode )    )
            {
                retState = Hash_Init_Dma( hashConfig );
            }
            else
            {
                /* POLL / ISR mode do not use Gpdma, or the interrupt configuration already failed */
            }
        }
        else
        {
            retState = HASH_REQUEST_ERROR;
        }

        if( HASH_REQUEST_OK == retState )
        {
            hash_RuntimeData.XferMode         = hashConfig->XferMode;
            hash_RuntimeData.DmaPeriphId       = hashConfig->DmaPeriphId;
            hash_RuntimeData.DmaChannelId      = hashConfig->DmaChannelId;
            hash_RuntimeData.DmaChannelPrio    = hashConfig->DmaChannelPrio;
            hash_RuntimeData.CompleteCallback  = hashConfig->CompleteCallback;
            hash_RuntimeData.ErrorCallback     = hashConfig->ErrorCallback;
            hash_RuntimeData.State             = HASH_STATE_IDLE;
            hash_RuntimeData.XferError         = HASH_XFER_ERROR_NONE;
            hash_RuntimeData.CalcOpen       = HASH_FUNCTION_INACTIVE;
            hash_RuntimeData.PendingCnt        = 0u;
            hash_RuntimeData.AnyWordWritten    = HASH_FUNCTION_INACTIVE;
            hash_RuntimeData.InitState         = HASH_FUNCTION_ACTIVE;

            if( HASH_XFER_MODE_ISR == hashConfig->XferMode )
            {
                Hash_Set_RegVal( HASH_REG_IMR, ( HASH_IMR_DCIE | HASH_IMR_DINIE ), ( HASH_IMR_DCIE | HASH_IMR_DINIE ) );
            }
            else
            {
                /* POLL / DMA mode do not use the data-input / digest-complete interrupt */
            }
        }
        else
        {
            /* Initialization failed, nothing else is configured */
        }
    }
    else
    {
        retState = HASH_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Deinitializes module Hash
 *
 * Disables the HASH interrupt in Nvic, stops a running DMA request and releases
 * the Gpdma channel (DMA mode), removes the user callbacks and marks the module
 * as not initialized (every other function returns \ref HASH_REQUEST_ERROR
 * afterwards). The peripheral clock is left active (shared Rcc resource).
 *
 * \return Function processing state. Returns \ref HASH_REQUEST_OK if request
 *         was processed without problems. Otherwise returns \ref HASH_REQUEST_ERROR.
 */
hash_RequestState_t Hash_Deinit( void )
{
    hash_RequestState_t       retState  = HASH_REQUEST_ERROR;
    const nvic_RequestState_t nvicState = Nvic_Set_PeriphIrq_Inactive( NVIC_PERIPH_IRQ_HASH );
    const hash_RequestState_t dmaState  = Hash_Release_Dma();

    if( HASH_FUNCTION_ACTIVE == hash_RuntimeData.InitState )
    {
        Hash_Stop_DmaHw();
    }
    else
    {
        /* The peripheral clock may be off, the registers are not accessed */
    }

    hash_RuntimeData.InitState       = HASH_FUNCTION_INACTIVE;
    hash_RuntimeData.CompleteCallback = HASH_NULL_PTR;
    hash_RuntimeData.ErrorCallback    = HASH_NULL_PTR;
    hash_RuntimeData.CalcOpen      = HASH_FUNCTION_INACTIVE;
    hash_RuntimeData.State            = HASH_STATE_IDLE;

    if( ( NVIC_REQUEST_OK == nvicState ) &&
        ( HASH_REQUEST_OK == dmaState  )    )
    {
        retState = HASH_REQUEST_OK;
    }
    else
    {
        retState = HASH_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Main task of module Hash
 *
 * In \ref HASH_XFER_MODE_POLL this module does all its work synchronously
 * inside \ref Hash_Set_Calculate / \ref Hash_Set_Update / \ref Hash_Set_Finish,
 * \ref Hash_Task has therefore nothing to do; it is kept for the interface
 * symmetry with the other data-transfer modules.
 */
void Hash_Task( void )
{
    /* No periodic work needed: POLL mode requests are served synchronously,
     * ISR / DMA mode requests are served by the interrupt handlers. */
}


/* ------------------------- Capability and state --------------------------- */

/**
 * \brief Tells in advance whether an algorithm is implemented by the device.
 *
 * \pre   Module shall be initialized (\ref Hash_Init), consistent with the other
 *        getters of the module (no side effects, error when not initialized);
 *        otherwise \ref HASH_REQUEST_ERROR.
 *
 * \param algorithm [in]:  Algorithm to query
 * \param supported [out]: \ref HASH_FUNCTION_ACTIVE if the device implements it. Must not be NULL.
 *
 * \return Function processing state. Returns \ref HASH_REQUEST_OK if request
 *         was processed without problems. Otherwise returns \ref HASH_REQUEST_ERROR.
 */
hash_RequestState_t Hash_Get_Capability( hash_Algorithm_t algorithm, hash_FunctionState_t * const supported )
{
    hash_RequestState_t retState = HASH_REQUEST_ERROR;

    if( ( HASH_FUNCTION_ACTIVE == hash_RuntimeData.InitState ) &&
        ( HASH_NULL_PTR        != supported                  ) &&
        ( HASH_ALGO_CNT        >  algorithm                  )    )
    {
        *supported = hash_AlgoLut[ algorithm ].Supported;
        retState   = HASH_REQUEST_OK;
    }
    else
    {
        retState = HASH_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Returns the digest size of an algorithm.
 *
 * \pre   Module shall be initialized (\ref Hash_Init), consistent with the other
 *        getters of the module (no side effects, error when not initialized);
 *        otherwise \ref HASH_REQUEST_ERROR.
 *
 * \param algorithm  [in]:  Algorithm to query
 * \param digestSize [out]: Digest size in bytes, 0 for \ref HASH_ALGO_SHAKE128 /
 *                          \ref HASH_ALGO_SHAKE256 (the requested length of the
 *                          extendable output is taken from the request instead).
 *                          Must not be NULL.
 *
 * \return Function processing state. Returns \ref HASH_REQUEST_OK if request
 *         was processed without problems. Otherwise returns \ref HASH_REQUEST_ERROR.
 */
hash_RequestState_t Hash_Get_DigestSize( hash_Algorithm_t algorithm, hash_DataCnt_t * const digestSize )
{
    hash_RequestState_t retState = HASH_REQUEST_ERROR;

    if( ( HASH_FUNCTION_ACTIVE == hash_RuntimeData.InitState ) &&
        ( HASH_NULL_PTR        != digestSize                 ) &&
        ( HASH_ALGO_CNT        >  algorithm                  )    )
    {
        *digestSize = hash_AlgoLut[ algorithm ].DigestSize;
        retState    = HASH_REQUEST_OK;
    }
    else
    {
        retState = HASH_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Returns the request processing state of the peripheral.
 *
 * \param hashState [out]: Pointer to store the state. Must not be NULL.
 *
 * \return Function processing state. Returns \ref HASH_REQUEST_OK if request
 *         was processed without problems. Otherwise returns \ref HASH_REQUEST_ERROR.
 */
hash_RequestState_t Hash_Get_State( hash_State_t * const hashState )
{
    hash_RequestState_t retState = HASH_REQUEST_ERROR;

    if( HASH_NULL_PTR != hashState )
    {
        if( HASH_FUNCTION_ACTIVE == hash_RuntimeData.InitState )
        {
            *hashState = hash_RuntimeData.State;
            retState   = HASH_REQUEST_OK;
        }
        else
        {
            retState = HASH_REQUEST_ERROR;
        }
    }
    else
    {
        retState = HASH_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Returns the active transfer error mask and clears it.
 *
 * \param xferError [out]: Pointer to store the error mask. Must not be NULL.
 *
 * \return Function processing state. Returns \ref HASH_REQUEST_OK if request
 *         was processed without problems. Otherwise returns \ref HASH_REQUEST_ERROR.
 */
hash_RequestState_t Hash_Get_XferError( hash_XferError_t * const xferError )
{
    hash_RequestState_t retState = HASH_REQUEST_ERROR;

    if( HASH_NULL_PTR != xferError )
    {
        *xferError = hash_RuntimeData.XferError;
        hash_RuntimeData.XferError = HASH_XFER_ERROR_NONE;
        retState = HASH_REQUEST_OK;
    }
    else
    {
        retState = HASH_REQUEST_ERROR;
    }

    return ( retState );
}


/* --------------------------------- One-shot -------------------------------- */

/**
 * \brief Computes the digest (or HMAC) of a complete buffer.
 *
 * Equivalent to \ref Hash_Set_Start, one \ref Hash_Set_Update with the whole
 * buffer and \ref Hash_Set_Finish, as one synchronous call in \ref HASH_XFER_MODE_POLL,
 * or started and completed through \ref HASH_XFER_MODE_ISR / \ref HASH_XFER_MODE_DMA
 * (digest ready is reported by the completion callback configured at \ref Hash_Init).
 *
 * \note  \ref HASH_XFER_MODE_DMA only accepts \ref HASH_MODE_HASH (not HMAC): the
 *        HMAC inner/outer key phases are not DMA transfers. The DMA reads the
 *        message as 32-bit words, so \ref hash_Request_t::Input must be word aligned.
 *        \p request is copied, but the input and the digest buffer must stay valid
 *        until the completion (or error) callback; the digest is written by the
 *        HASH interrupt.
 *
 * \pre   Module shall be initialized (\ref Hash_Init), the peripheral shall be
 *        idle (\ref Hash_Get_State), no incremental calculation open and \p request
 *        shall be valid (supported algorithm, non-NULL input/digest buffer for a
 *        non-zero size, digest buffer at least as long as the digest, DMA mode
 *        only with \ref HASH_MODE_HASH and a word-aligned input); otherwise
 *        \ref HASH_REQUEST_ERROR and the hardware is not touched.
 *
 * \param request [in]: Pointer to the request, see \ref hash_Request_t. Must not be NULL.
 *
 * \return Function processing state. Returns \ref HASH_REQUEST_OK if the request was
 *         accepted (the digest is ready already in POLL mode, later through the
 *         callback otherwise). Otherwise returns \ref HASH_REQUEST_ERROR.
 */
hash_RequestState_t Hash_Set_Calculate( const hash_Request_t * const request )
{
    hash_RequestState_t retState = HASH_REQUEST_ERROR;

    if( ( HASH_FUNCTION_ACTIVE   == hash_RuntimeData.InitState                    ) &&
        ( HASH_FUNCTION_INACTIVE == hash_RuntimeData.CalcOpen                     ) &&
        ( HASH_STATE_BUSY        != hash_RuntimeData.State                        ) &&
        ( HASH_NULL_PTR          != request                                       ) &&
        ( HASH_ALGO_CNT          >  request->Algorithm                            ) &&
        ( HASH_MODE_CNT          >  request->Mode                                 ) &&
        ( HASH_FUNCTION_ACTIVE   == hash_AlgoLut[ request->Algorithm ].Supported  ) &&
        ( ( HASH_NULL_PTR        != request->Input                           ) ||
          ( 0u                   == request->InputSize                       )    ) &&
        ( HASH_NULL_PTR          != request->Digest                               ) &&
        ( request->DigestSize    >= hash_AlgoLut[ request->Algorithm ].DigestSize )    )
    {
        if( HASH_XFER_MODE_DMA == hash_RuntimeData.XferMode )
        {
            const uint32_t inputAlign = ( (uint32_t)(uintptr_t)request->Input & HASH_WORD_ALIGN_MASK );

            if( ( HASH_MODE_HASH == request->Mode ) &&
                ( 0u             == inputAlign    )    )
            {
                retState = Hash_Calc_OneShot_Dma( request );
            }
            else
            {
                /* HMAC is not supported in DMA mode, the DMA reads the input as 32-bit words */
                retState = HASH_REQUEST_ERROR;
            }
        }
        else
        {
            retState = Hash_Calc_OneShot_Poll( request );
        }
    }
    else
    {
        retState = HASH_REQUEST_ERROR;
    }

    return ( retState );
}


/* -------------------------------- Incremental ------------------------------ */

/**
 * \brief Opens an incremental digest / HMAC calculation.
 *
 * For \ref HASH_MODE_HMAC the inner key is written and its intermediate digest
 * calculation is started right away (RM0481 HMAC operation, step 1 and 2); the
 * outer key is written again by \ref Hash_Set_Finish (step 4).
 *
 * \pre   Module shall be initialized, idle, in \ref HASH_XFER_MODE_POLL or
 *        \ref HASH_XFER_MODE_ISR (the incremental interface is not available in
 *        \ref HASH_XFER_MODE_DMA, see the module report), no calculation already
 *        open, \p startConfig shall be valid (supported algorithm, HMAC not
 *        combined with SHAKE, non-NULL key for a non-zero key size); otherwise
 *        \ref HASH_REQUEST_ERROR.
 *
 * \param startConfig [in]: Pointer to the start configuration, see \ref hash_StartConfig_t.
 *                          Must not be NULL.
 *
 * \return Function processing state. Returns \ref HASH_REQUEST_OK if request
 *         was processed without problems. Otherwise returns \ref HASH_REQUEST_ERROR.
 */
hash_RequestState_t Hash_Set_Start( const hash_StartConfig_t * const startConfig )
{
    hash_RequestState_t retState = HASH_REQUEST_ERROR;

    if( ( HASH_FUNCTION_ACTIVE   == hash_RuntimeData.InitState                       ) &&
        ( HASH_XFER_MODE_DMA     != hash_RuntimeData.XferMode                        ) &&
        ( HASH_FUNCTION_INACTIVE == hash_RuntimeData.CalcOpen                        ) &&
        ( HASH_STATE_BUSY        != hash_RuntimeData.State                           ) &&
        ( HASH_NULL_PTR          != startConfig                                      ) &&
        ( HASH_ALGO_CNT          >  startConfig->Algorithm                           ) &&
        ( HASH_MODE_CNT          >  startConfig->Mode                                ) &&
        ( HASH_FUNCTION_ACTIVE   == hash_AlgoLut[ startConfig->Algorithm ].Supported ) &&
        ( ( HASH_MODE_HASH       == startConfig->Mode                           ) ||
          ( ( HASH_ALGO_SHAKE128 != startConfig->Algorithm                 ) &&
            ( HASH_ALGO_SHAKE256 != startConfig->Algorithm                 )    )    ) &&
        ( ( HASH_NULL_PTR        != startConfig->Key                            ) ||
          ( 0u                   == startConfig->KeySize                        )    )    )
    {
        retState = Hash_Reg_Open_Calc( startConfig->Algorithm,
                                       startConfig->Mode,
                                       startConfig->Key,
                                       startConfig->KeySize );
    }
    else
    {
        retState = HASH_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Feeds a chunk of the message into the open calculation.
 *
 * Any size and alignment is accepted (also 0 and not a multiple of the word
 * size), the incomplete trailing bytes are kept in the module until the next
 * \ref Hash_Set_Update or \ref Hash_Set_Finish.
 *
 * \pre   A calculation shall be open (\ref Hash_Set_Start) and \p data shall not be
 *        NULL for a non-zero \p dataSize; otherwise \ref HASH_REQUEST_ERROR.
 *
 * \param data     [in]: Pointer to the message chunk. May be NULL only together with dataSize 0.
 * \param dataSize [in]: Size of the chunk in bytes.
 *
 * \return Function processing state. Returns \ref HASH_REQUEST_OK if request
 *         was processed without problems. Otherwise returns \ref HASH_REQUEST_ERROR.
 */
hash_RequestState_t Hash_Set_Update( const hash_Data_t * const data, hash_DataCnt_t dataSize )
{
    hash_RequestState_t retState = HASH_REQUEST_ERROR;

    if( ( HASH_FUNCTION_ACTIVE == hash_RuntimeData.CalcOpen ) &&
        ( ( HASH_NULL_PTR      != data                 ) ||
          ( 0u                 == dataSize             )    )    )
    {
        Hash_Push_Bytes( data, dataSize );
        retState = HASH_REQUEST_OK;
    }
    else
    {
        retState = HASH_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Finishes the open calculation and delivers the digest.
 *
 * Pads the message (HASH_STR.NBLW and DCAL), waits for the digest and, for
 * \ref HASH_MODE_HMAC, writes the outer key and waits again (RM0481 HMAC
 * operation, steps 3 and 4). The peripheral is idle again afterwards.
 *
 * \pre   A calculation shall be open and \p digest shall not be NULL with \p digestSize
 *        at least the digest size of the calculation's algorithm; otherwise
 *        \ref HASH_REQUEST_ERROR (the calculation is closed either way).
 *
 * \param digest     [out]: Output digest buffer. Must not be NULL.
 * \param digestSize [in]:  Size of \p digest in bytes.
 *
 * \return Function processing state. Returns \ref HASH_REQUEST_OK if the digest
 *         was delivered. Otherwise returns \ref HASH_REQUEST_ERROR.
 */
hash_RequestState_t Hash_Set_Finish( hash_Data_t * const digest, hash_DataCnt_t digestSize )
{
    hash_RequestState_t retState = HASH_REQUEST_ERROR;

    if( ( HASH_FUNCTION_ACTIVE == hash_RuntimeData.CalcOpen                                ) &&
        ( HASH_NULL_PTR        != digest                                                   ) &&
        ( digestSize           >= hash_AlgoLut[ hash_RuntimeData.CurAlgorithm ].DigestSize )    )
    {
        retState = Hash_Push_Final();

        if( ( HASH_REQUEST_OK == retState                 ) &&
            ( HASH_MODE_HMAC  == hash_RuntimeData.CurMode )    )
        {
            retState = Hash_Wait_DataInReady();

            if( HASH_REQUEST_OK == retState )
            {
                Hash_Push_Bytes( hash_RuntimeData.OuterKey, hash_RuntimeData.OuterKeySize );
                retState = Hash_Push_Final();
            }
            else
            {
                /* Peripheral did not become ready for the outer key phase */
            }
        }
        else
        {
            /* Plain hash, or the message phase already failed */
        }

        if( HASH_REQUEST_OK == retState )
        {
            retState = Hash_Wait_DigestReady();

            if( HASH_REQUEST_OK == retState )
            {
                Hash_Read_Digest( digest, digestSize );
                /* The digest is read, DCIS may be cleared now (HASH_HRx read as zero while DCIS = 0) */
                Hash_Reset_RegBit( HASH_REG_SR, HASH_SR_DCIS );
            }
            else
            {
                /* Digest never became ready within the timeout */
            }
        }
        else
        {
            /* Message or outer key phase failed, digest is not read */
        }

        hash_RuntimeData.CalcOpen = HASH_FUNCTION_INACTIVE;
        hash_RuntimeData.State       = HASH_STATE_IDLE;
    }
    else
    {
        retState = HASH_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Aborts the open calculation (and any ongoing DMA transfer) and clears the hardware.
 *
 * In \ref HASH_XFER_MODE_DMA the request is ended first (state IDLE, no callback
 * follows), then the Gpdma channel is stopped, the digest interrupt masked and
 * the DMA interface of the HASH disabled.
 *
 * \return Function processing state. Returns \ref HASH_REQUEST_OK if request
 *         was processed without problems. Otherwise (the Gpdma channel did not
 *         stop) returns \ref HASH_REQUEST_ERROR.
 */
hash_RequestState_t Hash_Set_Abort( void )
{
    hash_RequestState_t  retState = HASH_REQUEST_OK;
    gpdma_RequestState_t dmaState = GPDMA_REQUEST_OK;

    hash_RuntimeData.CalcOpen   = HASH_FUNCTION_INACTIVE;
    hash_RuntimeData.State          = HASH_STATE_IDLE;
    hash_RuntimeData.PendingCnt     = 0u;
    hash_RuntimeData.AnyWordWritten = HASH_FUNCTION_INACTIVE;
    hash_RuntimeData.DmaBodyLeft    = 0u;
    hash_RuntimeData.DmaTailBytes   = 0u;
    hash_RuntimeData.DmaLastChunk   = HASH_FUNCTION_INACTIVE;

    if( HASH_FUNCTION_ACTIVE == hash_RuntimeData.DmaInit )
    {
        dmaState = Gpdma_Set_ChannelInactive( hash_RuntimeData.DmaPeriphId, hash_RuntimeData.DmaChannelId );
        Hash_Stop_DmaHw();
    }
    else
    {
        /* DMA channel was not in use */
    }

    Hash_Set_RegBit( HASH_REG_CR, HASH_CR_INIT );

    if( GPDMA_REQUEST_OK != dmaState )
    {
        retState = HASH_REQUEST_ERROR;
    }
    else
    {
        retState = HASH_REQUEST_OK;
    }

    return ( retState );
}


/* ---------------------------- Suspend and resume --------------------------- */

/**
 * \brief Saves the current incremental calculation into an opaque context.
 *
 * Follows the data-loaded-by-software suspend sequence of RM0481/RM0492/RM0517
 * (HASH suspend/resume operations): waits for the peripheral to be ready
 * (\ref HASH_STATE_BUSY must not be the state), then reads HASH_IMR, HASH_STR,
 * HASH_CR and the HASH_CSRx registers of the open calculation's algorithm group.
 *
 * \pre   A calculation shall be open (between two \ref Hash_Set_Update calls, not
 *        right after \ref Hash_Set_Start before any data, see the README rules);
 *        otherwise \ref HASH_REQUEST_ERROR.
 *
 * \param context [out]: Pointer to store the context. Must not be NULL.
 *
 * \return Function processing state. Returns \ref HASH_REQUEST_OK if request
 *         was processed without problems. Otherwise returns \ref HASH_REQUEST_ERROR.
 */
hash_RequestState_t Hash_Get_Context( hash_Context_t * const context )
{
    hash_RequestState_t retState = HASH_REQUEST_ERROR;

    if( ( HASH_NULL_PTR        != context                   ) &&
        ( HASH_FUNCTION_ACTIVE == hash_RuntimeData.CalcOpen )    )
    {
        retState = Hash_Wait_DataInReady();

        if( HASH_REQUEST_OK == retState )
        {
            hash_ContextLayout_t * const layout = (hash_ContextLayout_t *)(void *)context;
            const uint32_t              csrCnt  = Hash_Calc_CsrCount( hash_RuntimeData.CurAlgorithm );

            uint32_t                    pendingWord = 0u;

            Hash_Reg_Save_Context( layout, csrCnt );

            /* The incomplete word is module state, not hardware state: it travels with the context */
            for( uint8_t idx = 0u; hash_RuntimeData.PendingCnt > idx; idx++ )
            {
                pendingWord |= ( (uint32_t)hash_RuntimeData.Pending[ idx ] << ( idx * HASH_BITS_PER_BYTE ) );
            }

            layout->PendingWord = pendingWord;
            layout->PendingCnt  = hash_RuntimeData.PendingCnt;

            hash_RuntimeData.PendingCnt = 0u;
            hash_RuntimeData.CalcOpen = HASH_FUNCTION_INACTIVE;
            hash_RuntimeData.State        = HASH_STATE_IDLE;
        }
        else
        {
            /* Peripheral never became ready, context is not saved */
        }
    }
    else
    {
        retState = HASH_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Restores a previously saved incremental calculation and reopens the calculation.
 *
 * Follows the resume sequence of RM0481/RM0492/RM0517 (HASH suspend/resume
 * operations): writes HASH_IMR, HASH_STR, HASH_CR, sets HASH_CR.INIT and writes
 * the HASH_CSRx registers back. The caller must keep the algorithm, mode and
 * remaining key (for the HMAC outer key phase) that were in use when the
 * context was taken, \ref hash_Context_t does not carry them.
 *
 * \pre   Module shall be initialized, idle, no calculation already open; otherwise
 *        \ref HASH_REQUEST_ERROR and nothing is written.
 *
 * \param context [in]: Pointer to the saved context. Must not be NULL.
 *
 * \return Function processing state. Returns \ref HASH_REQUEST_OK if request
 *         was processed without problems. Otherwise returns \ref HASH_REQUEST_ERROR.
 */
hash_RequestState_t Hash_Set_Context( const hash_Context_t * const context )
{
    hash_RequestState_t retState = HASH_REQUEST_ERROR;

    const hash_ContextLayout_t * const layout = (const hash_ContextLayout_t *)(const void *)context;

    if( ( HASH_NULL_PTR          != context                    ) &&
        ( HASH_FUNCTION_ACTIVE   == hash_RuntimeData.InitState ) &&
        ( HASH_FUNCTION_INACTIVE == hash_RuntimeData.CalcOpen  ) &&
        ( HASH_STATE_BUSY        != hash_RuntimeData.State     ) &&
        ( HASH_WORD_SIZE         >  layout->PendingCnt         )    )
    {
        uint32_t csrCnt = HASH_CSR_CNT_GROUP_SHORT;

#if defined( HASH_CR_ALGO_2 ) && \
    defined( HASH_CR_ALGO_3 )
        const uint32_t algoBits = ( layout->Cr & HASH_CR_ALGO );

        if( ( HASH_CR_ALGO_3 | HASH_CR_ALGO_2 ) == ( algoBits & ( HASH_CR_ALGO_3 | HASH_CR_ALGO_2 ) ) )
        {
            csrCnt = HASH_CSR_CNT_GROUP_LONG;
        }
        else if( HASH_CR_ALGO_2 == ( algoBits & HASH_CR_ALGO_2 ) )
        {
            csrCnt = HASH_CSR_CNT_GROUP_SHA3;
        }
        else
        {
            /* Short / SHA-1 group, csrCnt already set */
        }
#else
        /* HASH_CR.ALGO is only 2 bit wide on this line (H503): only the short
         * group (SHA-1 / SHA2-224 / SHA2-256) exists, csrCnt already set */
#endif /* HASH_CR_ALGO_2 && HASH_CR_ALGO_3 */

        Hash_Reg_Restore_Context( layout, csrCnt );

        hash_RuntimeData.CalcOpen    = HASH_FUNCTION_ACTIVE;
        hash_RuntimeData.State           = HASH_STATE_BUSY;
        for( uint8_t idx = 0u; layout->PendingCnt > idx; idx++ )
        {
            hash_RuntimeData.Pending[ idx ] = (uint8_t)( layout->PendingWord >> ( idx * HASH_BITS_PER_BYTE ) );
        }

        hash_RuntimeData.PendingCnt      = (uint8_t)layout->PendingCnt;
        hash_RuntimeData.AnyWordWritten  = HASH_FUNCTION_ACTIVE;
        retState = HASH_REQUEST_OK;
    }
    else
    {
        retState = HASH_REQUEST_ERROR;
    }

    return ( retState );
}


/* -------------------------------- Interrupts ------------------------------- */

/**
 * \brief Sets the HASH interrupt priority (ISR / DMA mode).
 *
 * \param irqPrio [in]: New interrupt priority (0 - highest priority)
 *
 * \return Function processing state. Returns \ref HASH_REQUEST_OK if request
 *         was processed without problems. Otherwise returns \ref HASH_REQUEST_ERROR.
 */
hash_RequestState_t Hash_Set_IrqPriority( hash_IrqPrio_t irqPrio )
{
    hash_RequestState_t       retState  = HASH_REQUEST_ERROR;
    const nvic_RequestState_t nvicState = Nvic_Set_PeriphIrq_Prio( NVIC_PERIPH_IRQ_HASH, irqPrio );

    if( NVIC_REQUEST_OK == nvicState )
    {
        retState = HASH_REQUEST_OK;
    }
    else
    {
        retState = HASH_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Returns the configured HASH interrupt priority.
 *
 * \param irqPrio [out]: Pointer to store the priority. Must not be NULL.
 *
 * \return Function processing state. Returns \ref HASH_REQUEST_OK if request
 *         was processed without problems. Otherwise returns \ref HASH_REQUEST_ERROR.
 */
hash_RequestState_t Hash_Get_IrqPriority( hash_IrqPrio_t * const irqPrio )
{
    hash_RequestState_t       retState  = HASH_REQUEST_ERROR;
    const nvic_RequestState_t nvicState = Nvic_Get_PeriphIrq_Prio( NVIC_PERIPH_IRQ_HASH, irqPrio );

    if( NVIC_REQUEST_OK == nvicState )
    {
        retState = HASH_REQUEST_OK;
    }
    else
    {
        retState = HASH_REQUEST_ERROR;
    }

    return ( retState );
}

/* =========================== LOCAL FUNCTIONS ============================== */

/**
 * \brief Returns the algorithm properties table entry, or \ref HASH_NULL_PTR for an invalid index.
 */
static const hash_AlgoProps_t *Hash_Get_AlgoProps( hash_Algorithm_t algorithm )
{
    const hash_AlgoProps_t *retProps = HASH_NULL_PTR;

    if( HASH_ALGO_CNT > algorithm )
    {
        retProps = &hash_AlgoLut[ algorithm ];
    }
    else
    {
        /* Invalid algorithm, NULL is returned */
    }

    return ( retProps );
}


/**
 * \brief Returns the conservative (HMAC-extended) context swap register count of
 *        the algorithm's group (RM0481/RM0492/RM0517 suspend/resume operations).
 */
static uint32_t Hash_Calc_CsrCount( hash_Algorithm_t algorithm )
{
    uint32_t retCnt = HASH_CSR_CNT_GROUP_SHORT;

    if( ( HASH_ALGO_SHA2_384     == algorithm ) ||
        ( HASH_ALGO_SHA2_512     == algorithm ) ||
        ( HASH_ALGO_SHA2_512_224 == algorithm ) ||
        ( HASH_ALGO_SHA2_512_256 == algorithm )    )
    {
        retCnt = HASH_CSR_CNT_GROUP_LONG;
    }
    else if( ( HASH_ALGO_SHA3_224 == algorithm ) ||
             ( HASH_ALGO_SHA3_256 == algorithm ) ||
             ( HASH_ALGO_SHA3_384 == algorithm ) ||
             ( HASH_ALGO_SHA3_512 == algorithm ) ||
             ( HASH_ALGO_SHAKE128 == algorithm ) ||
             ( HASH_ALGO_SHAKE256 == algorithm )    )
    {
        retCnt = HASH_CSR_CNT_GROUP_SHA3;
    }
    else
    {
        /* SHA-1 / SHA2-224 / SHA2-256 group, retCnt already set */
    }

    return ( retCnt );
}


/**
 * \brief Initializes the hash core for a new calculation (HASH_CR.INIT, ALGO, MODE,
 *        DATATYPE, LKEY) and, for HMAC, writes and starts the inner key phase
 *        (RM0481 HMAC operation, steps 1 and 2).
 */
static hash_RequestState_t Hash_Reg_Open_Calc( hash_Algorithm_t algorithm,
                                               hash_Mode_t mode,
                                               const hash_Data_t * const key,
                                               hash_DataCnt_t keySize )
{
    hash_RequestState_t     retState = HASH_REQUEST_ERROR;
    const hash_AlgoProps_t *props    = Hash_Get_AlgoProps( algorithm );

    if( HASH_NULL_PTR != props )
    {
        uint32_t crValue = ( props->AlgoCrValue | HASH_CR_DATATYPE_1 | HASH_CR_INIT );

        if( HASH_MODE_HMAC == mode )
        {
            crValue |= HASH_CR_MODE;

            if( keySize > props->BlockSize )
            {
                crValue |= HASH_CR_LKEY;
            }
            else
            {
                /* Short key, LKEY stays cleared */
            }
        }
        else
        {
            /* Plain hash, MODE / LKEY stay cleared */
        }

        Hash_Set_RegVal( HASH_REG_CR, HASH_REG_FULL_MASK, crValue );

        hash_RuntimeData.CurAlgorithm    = algorithm;
        hash_RuntimeData.CurMode         = mode;
        hash_RuntimeData.OuterKey        = key;
        hash_RuntimeData.OuterKeySize    = keySize;
        hash_RuntimeData.PendingCnt      = 0u;
        hash_RuntimeData.AnyWordWritten  = HASH_FUNCTION_INACTIVE;
        hash_RuntimeData.CalcOpen     = HASH_FUNCTION_ACTIVE;
        hash_RuntimeData.State            = HASH_STATE_BUSY;

        retState = HASH_REQUEST_OK;

        if( HASH_MODE_HMAC == mode )
        {
            Hash_Push_Bytes( key, keySize );
            retState = Hash_Push_Final();

            if( HASH_REQUEST_OK == retState )
            {
                retState = Hash_Wait_DataInReady();
            }
            else
            {
                /* Inner key phase already failed */
            }
        }
        else
        {
            /* Plain hash, message phase starts with Hash_Set_Update */
        }
    }
    else
    {
        retState = HASH_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Pushes one little-endian packed 32-bit word to HASH_DIN (DATATYPE = byte
 *        swap, RM0481/RM0492/RM0517 message data feeding: the first byte of the
 *        string is placed at bits 7..0 of the word, as in memory - message "abc"
 *        is the word 0x00636261 - and the peripheral swaps the bytes itself).
 */
static void Hash_Push_Word( uint32_t word )
{
    Hash_Set_RegVal( HASH_REG_DIN, HASH_REG_FULL_MASK, word );
    hash_RuntimeData.AnyWordWritten = HASH_FUNCTION_ACTIVE;
}


/**
 * \brief Accumulates bytes into 32-bit words and pushes every full word to HASH_DIN.
 *        Up to 3 trailing bytes stay buffered in \ref hash_RuntimeData_t::Pending.
 */
static void Hash_Push_Bytes( const hash_Data_t * const data, hash_DataCnt_t dataSize )
{
    for( hash_DataCnt_t byteIdx = 0u; dataSize > byteIdx; byteIdx++ )
    {
        hash_RuntimeData.Pending[ hash_RuntimeData.PendingCnt ] = data[ byteIdx ];
        hash_RuntimeData.PendingCnt++;

        if( HASH_WORD_SIZE == hash_RuntimeData.PendingCnt )
        {
            uint32_t word = 0u;

            for( uint8_t wordIdx = 0u; HASH_WORD_SIZE > wordIdx; wordIdx++ )
            {
                const uint32_t shift = ( wordIdx * HASH_BITS_PER_BYTE );

                word |= ( (uint32_t)hash_RuntimeData.Pending[ wordIdx ] << shift );
            }

            Hash_Push_Word( word );
            hash_RuntimeData.PendingCnt = 0u;
        }
        else
        {
            /* Word not complete yet */
        }
    }
}


/**
 * \brief Pushes the pending (possibly empty) trailing word with the correct
 *        HASH_STR.NBLW and starts the final digest calculation (DCAL).
 */
static hash_RequestState_t Hash_Push_Final( void )
{
    hash_RequestState_t retState = HASH_REQUEST_ERROR;
    uint32_t             nblw     = HASH_NBLW_ALL_VALID;

    if( 0u < hash_RuntimeData.PendingCnt )
    {
        uint32_t word = 0u;

        for( uint8_t idx = 0u; hash_RuntimeData.PendingCnt > idx; idx++ )
        {
            const uint32_t shift = ( idx * HASH_BITS_PER_BYTE );

            word |= ( (uint32_t)hash_RuntimeData.Pending[ idx ] << shift );
        }

        Hash_Push_Word( word );
        nblw = ( (uint32_t)hash_RuntimeData.PendingCnt * HASH_BITS_PER_BYTE );
        hash_RuntimeData.PendingCnt = 0u;
    }
    else if( HASH_FUNCTION_INACTIVE == hash_RuntimeData.AnyWordWritten )
    {
        /* Empty message: no word is written, the hash core pads it at DCAL (a written zero word would be
         * hashed as four message bytes, NBLW = 0 means all 32 bits of the last written word are valid) */
        nblw = HASH_NBLW_ALL_VALID;
    }
    else
    {
        /* Last chunk ended exactly on a word boundary, NBLW stays "all valid" */
    }

    Hash_Set_RegVal( HASH_REG_STR, HASH_STR_NBLW, nblw );
    Hash_Set_RegBit( HASH_REG_STR, HASH_STR_DCAL );
    hash_RuntimeData.AnyWordWritten = HASH_FUNCTION_INACTIVE;

    retState = HASH_REQUEST_OK;

    return ( retState );
}


/**
 * \brief Waits (bounded loop) for HASH_SR.DINIS (peripheral ready for the next
 *        key / message phase, or for \ref Hash_Get_Context to read the HASH_CSRx).
 */
static hash_RequestState_t Hash_Wait_DataInReady( void )
{
    hash_RequestState_t retState = HASH_REQUEST_ERROR;

    for( uint32_t iterationCnt = 0u; HASH_POLL_TIMEOUT_RAW > iterationCnt; iterationCnt++ )
    {
        const uint32_t statusReg = Hash_Get_RegVal( HASH_REG_SR, ( HASH_SR_DINIS | HASH_SR_BUSY ) );

        if( ( HASH_SR_DINIS == ( statusReg & HASH_SR_DINIS ) ) &&
            ( 0u            == ( statusReg & HASH_SR_BUSY )  )    )
        {
            retState = HASH_REQUEST_OK;
            break;
        }
        else
        {
            /* Peripheral not ready yet */
            retState = HASH_REQUEST_ERROR;
        }
    }

    return ( retState );
}


/**
 * \brief Waits (bounded loop) for HASH_SR.DCIS (digest ready). The flag is NOT cleared here: while DCIS
 *        is 0 the HASH_HRx registers return zeros (RM0481 HASH_SR.DCIS), so the digest has to be read
 *        first and the flag is cleared afterwards by \ref Hash_Set_Finish.
 */
static hash_RequestState_t Hash_Wait_DigestReady( void )
{
    hash_RequestState_t retState = HASH_REQUEST_ERROR;

    for( uint32_t iterationCnt = 0u; HASH_POLL_TIMEOUT_RAW > iterationCnt; iterationCnt++ )
    {
        const uint32_t statusReg = Hash_Get_RegVal( HASH_REG_SR, HASH_SR_DCIS );

        if( HASH_SR_DCIS == statusReg )
        {
            retState = HASH_REQUEST_OK;
            break;
        }
        else
        {
            /* Digest not ready yet */
            retState = HASH_REQUEST_ERROR;
        }
    }

    return ( retState );
}


/**
 * \brief Reads the ready digest from HASH_HRx into the output buffer, most
 *        significant byte first (RM0481/RM0492/RM0517 HASH digest registers).
 */
static void Hash_Read_Digest( hash_Data_t * const digest, hash_DataCnt_t digestSize )
{
    const hash_AlgoProps_t *props   = Hash_Get_AlgoProps( hash_RuntimeData.CurAlgorithm );
    hash_DataCnt_t            copySize = digestSize;

    if( ( HASH_NULL_PTR             != props             ) &&
        ( HASH_DIGEST_SIZE_VARIABLE != props->DigestSize ) &&
        ( props->DigestSize         <  copySize          )    )
    {
        copySize = props->DigestSize;
    }
    else
    {
        /* Variable length output (SHAKE), the whole requested size is read */
    }

    for( hash_DataCnt_t byteIdx = 0u; copySize > byteIdx; byteIdx++ )
    {
        const uint32_t wordIdx  = ( byteIdx / HASH_WORD_SIZE );
        const uint32_t byteShift = ( ( ( HASH_WORD_SIZE - 1u ) - ( byteIdx % HASH_WORD_SIZE ) ) * HASH_BITS_PER_BYTE );
        const uint32_t word      = Hash_Reg_Get_DigestWord( wordIdx );

        digest[ byteIdx ] = (hash_Data_t)( word >> byteShift );
    }
}


/**
 * \brief Serves a one-shot request synchronously (POLL mode) or starts it and
 *        returns (ISR mode, the completion callback reports the end).
 */
static hash_RequestState_t Hash_Calc_OneShot_Poll( const hash_Request_t * const request )
{
    hash_RequestState_t retState = Hash_Reg_Open_Calc( request->Algorithm,
                                                       request->Mode,
                                                       request->Key,
                                                       request->KeySize );

    if( HASH_REQUEST_OK == retState )
    {
        Hash_Push_Bytes( request->Input, request->InputSize );
        retState = Hash_Set_Finish( request->Digest, request->DigestSize );

        if( ( HASH_REQUEST_OK    == retState                          ) &&
            ( HASH_XFER_MODE_ISR == hash_RuntimeData.XferMode         ) &&
            ( HASH_NULL_PTR      != hash_RuntimeData.CompleteCallback )    )
        {
            hash_RuntimeData.CompleteCallback();
        }
        else
        {
            /* POLL mode has already delivered the digest synchronously */
        }
    }
    else
    {
        /* Inner key phase of an HMAC request already failed */
    }

    return ( retState );
}


/**
 * \brief Starts a one-shot plain hash request through Gpdma (DMA mode, \ref HASH_MODE_HASH only).
 *
 * Programs HASH_STR.NBLW (valid bits of the last word) before the transfer starts (RM0481/RM0492/RM0517 HASH
 * DMA interface), keeps the digest buffer and the word-aligned copy of the 0..15 trailing bytes for the later
 * chunks and starts the first chunk. An empty message is padded by software (\ref Hash_Push_Final) and ends
 * through the digest interrupt like a transferred one.
 */
static hash_RequestState_t Hash_Calc_OneShot_Dma( const hash_Request_t * const request )
{
    const hash_DataCnt_t tailBytes = ( request->InputSize % HASH_DMA_CHUNK_ALIGN );
    const hash_DataCnt_t bodyBytes = ( request->InputSize - tailBytes );
    hash_RequestState_t  retState  = Hash_Reg_Open_Calc( request->Algorithm, request->Mode, HASH_NULL_PTR, 0u );

    if( HASH_REQUEST_OK == retState )
    {
        /* One-shot request: the incremental interface (Hash_Set_Update / Finish / Get_Context) stays closed */
        hash_RuntimeData.CalcOpen     = HASH_FUNCTION_INACTIVE;
        hash_RuntimeData.Digest       = request->Digest;
        hash_RuntimeData.DigestSize   = request->DigestSize;
        hash_RuntimeData.DmaNextAddr  = (uint32_t)(uintptr_t)request->Input;
        hash_RuntimeData.DmaBodyLeft  = bodyBytes;
        hash_RuntimeData.DmaTailBytes = tailBytes;
        hash_RuntimeData.DmaLastChunk = HASH_FUNCTION_INACTIVE;

        if( 0u < request->InputSize )
        {
            Hash_Fill_DmaTail( &request->Input[ bodyBytes ], tailBytes );
            Hash_Set_RegVal( HASH_REG_STR,
                             HASH_STR_NBLW,
                             ( ( request->InputSize % HASH_WORD_SIZE ) * HASH_BITS_PER_BYTE ) );

            retState = Hash_Start_DmaChunk();
        }
        else
        {
            /* Nothing to transfer: the message is padded by software, the digest interrupt ends the request */
            retState = Hash_Push_Final();
            Hash_Set_RegBit( HASH_REG_IMR, HASH_IMR_DCIE );
        }

        if( HASH_REQUEST_OK != retState )
        {
            Hash_Stop_DmaHw();
            hash_RuntimeData.State = HASH_STATE_IDLE;
        }
        else
        {
            /* The request runs, the digest interrupt or a Gpdma error ends it */
        }
    }
    else
    {
        /* The calculation could not be opened */
    }

    return ( retState );
}


/**
 * \brief Initializes the Gpdma channel of the DMA mode (memory to HASH_DIN, 32-bit words, single requests of the
 *        HASH, error mask without the suspension) and activates its interrupt. The block size and the source
 *        address are set per chunk by \ref Hash_Start_DmaChunk.
 */
static hash_RequestState_t Hash_Init_Dma( const hash_Config_t * const hashConfig )
{
    hash_RequestState_t    retState   = HASH_REQUEST_ERROR;
    gpdma_ConfigStruct_t   dmaConfig  = { 0 };
    gpdma_TransferConfig_t xferConfig = { 0 };
    gpdma_RequestState_t   dmaState   = Gpdma_Get_DefaultConfig( &dmaConfig );

    xferConfig.Direction                   = GPDMA_DIR_MEMORY_TO_PERIPH;
    xferConfig.XferListExecMode            = GPDMA_XFER_LIST_EXEC_ONCE;
    xferConfig.EventMode                   = GPDMA_TRANSFER_EVENT_BLOCK;
    xferConfig.TriggerType                 = GPDMA_TRG_NOT_USED;
    xferConfig.TriggerSource               = GPDMA_TRG_EXTI_LINE0;
    xferConfig.TriggerMode                 = GPDMA_TRIGGER_BLOCK;
    xferConfig.RequestSource               = GPDMA_REQ_HASH_IN;
    xferConfig.RequestMode                 = GPDMA_PERIPH_REQ_SINGLE;
    xferConfig.BlockSize                   = 0u; /* Set per chunk by Hash_Start_DmaChunk */
    xferConfig.BlockRepetitionCount        = 0u;
    xferConfig.SourceAddr                  = 0u; /* Set per chunk by Hash_Start_DmaChunk */
    xferConfig.SourceDataSize              = GPDMA_DATA_SIZE_32BITS;
    xferConfig.SourceBurstLength           = 1u;
    xferConfig.SourceAddrMode              = GPDMA_ADDR_INCREMENT;
    xferConfig.SourcePortId                = GPDMA_PORT_DEFAULT;
    xferConfig.SourceDataOp                = GPDMA_SRC_DATA_PRESERVE;
    xferConfig.SourceBlockOffset2D         = 0u;
    xferConfig.SourceRepBlockOffset2D      = 0u;
    xferConfig.DestinationAddr             = (gpdma_DstAddr_t)Hash_Reg_Get_DinAddr();
    xferConfig.DestinationDataSize         = GPDMA_DATA_SIZE_32BITS;
    xferConfig.DestinationBurstLength      = 1u;
    xferConfig.DestinationAddrMode         = GPDMA_ADDR_STATIC;
    xferConfig.DestinationPortId           = GPDMA_PORT_DEFAULT;
    xferConfig.DestinationDataOp           = GPDMA_DEST_DATA_PRESERVE;
    xferConfig.DestinationBlockOffset2D    = 0u;
    xferConfig.DestinationRepBlockOffset2D = 0u;

    dmaConfig.PeriphId            = hashConfig->DmaPeriphId;
    dmaConfig.ChannelId           = hashConfig->DmaChannelId;
    dmaConfig.ChannelPrio         = hashConfig->DmaChannelPrio;
    dmaConfig.TransferExecMode    = GPDMA_XFER_EXEC_BLOCKING;
    dmaConfig.TransferConfig      = &xferConfig;
    dmaConfig.TransfersCount      = 1u;
    dmaConfig.XferListAccessMode  = GPDMA_TRANSFER_LIST_ACCESS_SINGLE;
    dmaConfig.XferList            = &hash_DmaXferList[ 0 ];
    dmaConfig.TransferLockState   = GPDMA_TRANSFER_LIST_LOCKED;
    dmaConfig.TransferCompleteIsr = Hash_DmaCompleteIsr;
    dmaConfig.HalfTransferIsr     = HASH_NULL_PTR;
    dmaConfig.ErrorIsr            = Hash_DmaErrorIsr;
    dmaConfig.ErrorMask           = HASH_DMA_ERROR_MASK;

    if( GPDMA_REQUEST_OK == dmaState )
    {
        dmaState = Gpdma_Init( &dmaConfig );
    }
    else
    {
        /* The default configuration is not available */
    }

    if( GPDMA_REQUEST_OK == dmaState )
    {
        hash_RuntimeData.DmaInit      = HASH_FUNCTION_ACTIVE;
        hash_RuntimeData.DmaPeriphId  = hashConfig->DmaPeriphId;
        hash_RuntimeData.DmaChannelId = hashConfig->DmaChannelId;

        dmaState = Gpdma_Set_InterruptActive( hashConfig->DmaPeriphId, hashConfig->DmaChannelId );
    }
    else
    {
        /* The channel initialization failed */
    }

    if( GPDMA_REQUEST_OK == dmaState )
    {
        retState = HASH_REQUEST_OK;
    }
    else
    {
        retState = HASH_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Releases the Gpdma channel of the DMA mode (\ref Gpdma_Deinit stops a running transfer) and deactivates
 *        its interrupt. Nothing is done when no channel is initialized.
 */
static hash_RequestState_t Hash_Release_Dma( void )
{
    hash_RequestState_t  retState = HASH_REQUEST_OK;
    gpdma_RequestState_t dmaState = GPDMA_REQUEST_OK;

    if( HASH_FUNCTION_ACTIVE == hash_RuntimeData.DmaInit )
    {
        dmaState = Gpdma_Deinit( hash_RuntimeData.DmaPeriphId, hash_RuntimeData.DmaChannelId );

        if( GPDMA_REQUEST_OK == dmaState )
        {
            dmaState = Gpdma_Set_InterruptInactive( hash_RuntimeData.DmaPeriphId, hash_RuntimeData.DmaChannelId );
        }
        else
        {
            /* The channel did not stop, it stays initialized */
        }

        if( GPDMA_REQUEST_OK == dmaState )
        {
            hash_RuntimeData.DmaInit = HASH_FUNCTION_INACTIVE;
            retState                 = HASH_REQUEST_OK;
        }
        else
        {
            retState = HASH_REQUEST_ERROR;
        }
    }
    else
    {
        /* No Gpdma channel is initialized */
    }

    return ( retState );
}


/**
 * \brief Copies the 0..15 trailing bytes of a DMA request into the word-aligned \ref hash_DmaTail, packed as
 *        \ref Hash_Push_Bytes packs them (memory order, first byte at bits 7..0), the unused bytes are zero.
 */
static void Hash_Fill_DmaTail( const hash_Data_t * const data, hash_DataCnt_t dataSize )
{
    for( uint32_t wordIdx = 0u; HASH_DMA_TAIL_WORDS > wordIdx; wordIdx++ )
    {
        hash_DmaTail[ wordIdx ] = 0u;
    }

    for( hash_DataCnt_t byteIdx = 0u; dataSize > byteIdx; byteIdx++ )
    {
        const uint32_t wordIdx = ( byteIdx / HASH_WORD_SIZE );
        const uint32_t shift   = ( ( byteIdx % HASH_WORD_SIZE ) * HASH_BITS_PER_BYTE );

        hash_DmaTail[ wordIdx ] |= ( (uint32_t)data[ byteIdx ] << shift );
    }
}


/**
 * \brief Starts the next DMA chunk of the running request: a part of the message (a multiple of four words, at
 *        most \ref HASH_DMA_CHUNK_MAX bytes) or, after it, the trailing bytes from \ref hash_DmaTail rounded up to
 *        whole words (NBLW tells the valid bits of the last one). HASH_CR.MDMAT is set for every chunk except the
 *        last one, the HASH sets DCAL itself at the end of the last chunk. HASH_CR.DMAE is set for every chunk
 *        (the HASH clears it at the end of each transfer).
 */
static hash_RequestState_t Hash_Start_DmaChunk( void )
{
    hash_RequestState_t  retState  = HASH_REQUEST_ERROR;
    gpdma_RequestState_t dmaState  = GPDMA_REQUEST_ERROR;
    uint32_t             srcAddr   = hash_RuntimeData.DmaNextAddr;
    hash_DataCnt_t       chunkSize = hash_RuntimeData.DmaBodyLeft;

    if( 0u < hash_RuntimeData.DmaBodyLeft )
    {
        if( HASH_DMA_CHUNK_MAX < chunkSize )
        {
            chunkSize = HASH_DMA_CHUNK_MAX;
        }
        else
        {
            /* The rest of the message fits one chunk */
        }

        hash_RuntimeData.DmaNextAddr += chunkSize;
        hash_RuntimeData.DmaBodyLeft -= chunkSize;
    }
    else
    {
        srcAddr   = (uint32_t)(uintptr_t)&hash_DmaTail[ 0 ];
        chunkSize = ( ( hash_RuntimeData.DmaTailBytes + HASH_WORD_ALIGN_MASK ) & ~HASH_WORD_ALIGN_MASK );
        hash_RuntimeData.DmaTailBytes = 0u;
    }

    if( ( 0u == hash_RuntimeData.DmaBodyLeft  ) &&
        ( 0u == hash_RuntimeData.DmaTailBytes )    )
    {
        hash_RuntimeData.DmaLastChunk = HASH_FUNCTION_ACTIVE;
        Hash_Reset_RegBit( HASH_REG_CR, HASH_CR_MDMAT );
    }
    else
    {
        Hash_Set_RegBit( HASH_REG_CR, HASH_CR_MDMAT );
    }

    dmaState = Gpdma_Set_BlockSize( hash_RuntimeData.DmaPeriphId,
                                    hash_RuntimeData.DmaChannelId,
                                    (gpdma_BlockSize_t)chunkSize );

    if( GPDMA_REQUEST_OK == dmaState )
    {
        dmaState = Gpdma_Set_SourceAddr( hash_RuntimeData.DmaPeriphId,
                                         hash_RuntimeData.DmaChannelId,
                                         (gpdma_SrcAddr_t)srcAddr );
    }
    else
    {
        /* The block size was not accepted */
    }

    if( GPDMA_REQUEST_OK == dmaState )
    {
        /* A channel stopped by Hash_Set_Abort() was reset and lost its destination address */
        dmaState = Gpdma_Set_DestinationAddr( hash_RuntimeData.DmaPeriphId,
                                              hash_RuntimeData.DmaChannelId,
                                              (gpdma_DstAddr_t)Hash_Reg_Get_DinAddr() );
    }
    else
    {
        /* The source address was not accepted */
    }

    if( GPDMA_REQUEST_OK == dmaState )
    {
        /* The HASH clears DMAE at the end of every DMA transfer, also with MDMAT set: set again for every chunk */
        Hash_Set_RegBit( HASH_REG_CR, HASH_CR_DMAE );
        dmaState = Gpdma_Set_ChannelActive( hash_RuntimeData.DmaPeriphId, hash_RuntimeData.DmaChannelId );
    }
    else
    {
        /* The destination address was not accepted */
    }

    if( GPDMA_REQUEST_OK == dmaState )
    {
        retState = HASH_REQUEST_OK;
    }
    else
    {
        retState = HASH_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Masks the digest complete interrupt and disables the DMA interface of the HASH (DMAE, MDMAT).
 */
static void Hash_Stop_DmaHw( void )
{
    Hash_Reset_RegBit( HASH_REG_IMR, HASH_IMR_DCIE );
    Hash_Reset_RegBit( HASH_REG_CR, ( HASH_CR_DMAE | HASH_CR_MDMAT ) );
}


/**
 * \brief HASH interrupt handler.
 *
 * DMA mode: the digest complete interrupt (enabled after the last DMA chunk) reads the digest into the request
 * buffer, clears DCIS (only after the read, the HASH_HRx registers read as zero while DCIS = 0), ends the request
 * and calls the completion callback.
 * ISR mode: masks the DCIE / DINIE sources, the pending flags stay set because \ref Hash_Set_Finish polls them;
 * the completion callback is called from \ref Hash_Calc_OneShot_Poll synchronously in this driver version.
 */
static void Hash_IsrHandler( void )
{
    const uint32_t dcisFlag = Hash_Get_RegBit( HASH_REG_SR, HASH_SR_DCIS );

    if( ( HASH_XFER_MODE_DMA == hash_RuntimeData.XferMode ) &&
        ( HASH_STATE_BUSY    == hash_RuntimeData.State    ) &&
        ( HASH_SR_DCIS       == dcisFlag                  )    )
    {
        Hash_Stop_DmaHw();
        Hash_Read_Digest( hash_RuntimeData.Digest, hash_RuntimeData.DigestSize );
        Hash_Reset_RegBit( HASH_REG_SR, HASH_SR_DCIS );

        hash_RuntimeData.DmaLastChunk = HASH_FUNCTION_INACTIVE;
        hash_RuntimeData.State        = HASH_STATE_IDLE;

        if( HASH_NULL_PTR != hash_RuntimeData.CompleteCallback )
        {
            hash_RuntimeData.CompleteCallback();
        }
        else
        {
            /* No user callback configured */
        }
    }
    else
    {
        Hash_Reset_RegBit( HASH_REG_IMR, ( HASH_IMR_DCIE | HASH_IMR_DINIE ) );
    }
}


/**
 * \brief Gpdma transfer complete callback of the DMA request: starts the next chunk or, after the last chunk (the
 *        HASH sets DCAL itself), enables the digest complete interrupt that ends the request
 *        (\ref Hash_IsrHandler). DCIE is enabled only now, so the digest is never taken before the transfer of
 *        the last chunk is complete. A chunk that cannot be started ends the request with a DMA error.
 */
static void Hash_DmaCompleteIsr( void )
{
    if( HASH_STATE_BUSY == hash_RuntimeData.State )
    {
        if( HASH_FUNCTION_ACTIVE == hash_RuntimeData.DmaLastChunk )
        {
            Hash_Set_RegBit( HASH_REG_IMR, HASH_IMR_DCIE );
        }
        else
        {
            const hash_RequestState_t chunkState = Hash_Start_DmaChunk();

            if( HASH_REQUEST_OK != chunkState )
            {
                Hash_DmaErrorIsr( GPDMA_ERROR_CONFIG_ERROR );
            }
            else
            {
                /* The next chunk runs */
            }
        }
    }
    else
    {
        /* The request was aborted meanwhile, nothing to continue */
    }
}


/**
 * \brief Gpdma transfer error callback of the DMA request: stops the DMA interface of the HASH, ends the request
 *        with \ref HASH_STATE_ERROR and \ref HASH_XFER_ERROR_DMA and calls the error callback. An error after the
 *        request was aborted is not reported.
 */
static void Hash_DmaErrorIsr( gpdma_ErrorMaskId_t errMask )
{
    (void)errMask;

    if( HASH_STATE_BUSY == hash_RuntimeData.State )
    {
        Hash_Stop_DmaHw();

        hash_RuntimeData.DmaBodyLeft  = 0u;
        hash_RuntimeData.DmaTailBytes = 0u;
        hash_RuntimeData.DmaLastChunk = HASH_FUNCTION_INACTIVE;
        hash_RuntimeData.State        = HASH_STATE_ERROR;
        hash_RuntimeData.XferError   |= HASH_XFER_ERROR_DMA;

        if( HASH_NULL_PTR != hash_RuntimeData.ErrorCallback )
        {
            hash_RuntimeData.ErrorCallback( hash_RuntimeData.XferError );
        }
        else
        {
            /* No user callback configured */
        }
    }
    else
    {
        /* No request runs, the error is not reported */
    }
}

/* =========================== INTERRUPT HANDLERS =========================== */

/* ================================ TASKS =================================== */
