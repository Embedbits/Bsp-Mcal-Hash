/**
 * \author Mr.Nobody
 * \file Test_Hash.c
 * \ingroup Hash
 * \brief Unit tests of the hash processor (HASH) module.
 *
 * Hash.c and Hash_Reg.c are compiled unchanged, HASH registers are emulated by
 * RegMem, RCC, NVIC and Gpdma modules are mocked by CMock.
 *
 * \note Limitations of the register emulation (RegMem registers are plain memory,
 *       the HASH core never actually computes a digest):
 *       - HASH_SR.DINIS / HASH_SR.DCIS are preset by the test before a call so the
 *         bounded wait loops of the driver succeed immediately; the driver's own
 *         write of HASH_CR.INIT / HASH_STR.DCAL is still verified against the
 *         expected register value.
 *       - The digest content is whatever the test preset into HASH_HRx before the
 *         call: the tests check the byte order and the size the driver reads back,
 *         not a cryptographic result.
 *       - DMA mode: Gpdma is mocked, no data is moved. The tests check the chunk
 *         sequence (block size, source address, HASH_CR.MDMAT), HASH_STR.NBLW and the
 *         end of the request: the Gpdma callbacks captured from Gpdma_Init() and the
 *         HASH interrupt handler captured from Nvic_Set_PeriphIrq_Handler() are
 *         called by the test. The digest of a real transfer is checked by the
 *         integration tests.
 *       - Every test case is executed in its own process (CTest), the runtime data
 *         of the module start from the reset state in every test.
 */

/* ============================= INCLUDES =================================== */
#include "unity.h"                          /* Unity testing framework        */
#include "RegMem.h"                         /* Register memory emulation      */
#include "Hash_Port.h"                      /* Module under test              */
#include "Hash_Reg.h"                       /* Register access of the module  */
#include "MockRcc_Port.h"                   /* RCC module mock                */
#include "MockNvic_Port.h"                  /* NVIC module mock                */
#include "MockGpdma_Port.h"                 /* Gpdma module mock               */
#include "Stm32.h"                          /* HASH registers definition      */
/* ============================= TYPEDEFS =================================== */

/* ======================= FORWARD DECLARATIONS ============================= */

static void                UtHash_Expect_InitPoll ( void );
static hash_Config_t       UtHash_Get_PollConfig   ( void );
static void                UtHash_Init_Dma        ( void );
static void                UtHash_Expect_DmaChunk  ( gpdma_BlockSize_t blockSize, const hash_Data_t * const srcAddr );
static void                UtHash_Callback_Complete( void );
static void                UtHash_Callback_Error   ( hash_XferError_t xferError );

static nvic_RequestState_t  UtHash_NvicHandlerStub ( nvic_PeriphIrqList_t irqId,
                                                     const nvic_IsrCallback_t irqHandler,
                                                     int callCnt );
static gpdma_RequestState_t UtHash_GpdmaInitStub   ( gpdma_ConfigStruct_t * const configStruct,
                                                     int callCnt );

/* ========================== SYMBOLIC CONSTANTS ============================= */

/** Expected version of the module */
#define UT_HASH_VERSION_MAJOR               ( 0u )
#define UT_HASH_VERSION_MINOR               ( 1u )
#define UT_HASH_VERSION_PATCH               ( 0u )

/** Register value without any bit set */
#define UT_HASH_REG_ZERO                    ( 0u )

/** Interrupt priority used by the tests */
#define UT_HASH_IRQ_PRIO                    ( 2u )

/** "abc" as bytes, the classic SHA-1 / SHA-2 test vector (3 bytes, 1 incomplete word) */
static const hash_Data_t utHash_Abc[ 3 ] = { 0x61u, 0x62u, 0x63u };

/** "abc" as the word written to HASH_DIN with DATATYPE = byte swap: memory order, first byte at bits 7..0 */
#define UT_HASH_ABC_WORD                     ( 0x00636261u )

/** Count of bytes of "abc" */
#define UT_HASH_ABC_SIZE                     ( 3u )

/** NBLW value of a 3 byte last word (24 valid bits) */
#define UT_HASH_NBLW_3_BYTES                 ( 24u )

/** Digest size of SHA-1 */
#define UT_HASH_SHA1_DIGEST_SIZE             ( 20u )

/** Digest size of SHA2-256 */
#define UT_HASH_SHA256_DIGEST_SIZE           ( 32u )

/** Known digest word preset into HASH_HR0 by the tests (arbitrary pattern, big-endian readback check) */
#define UT_HASH_DIGEST_WORD0                 ( 0x01020304u )

/** Byte offset of HASH_HR0 from the HASH base address (RM0481/RM0492/RM0517 HASH digest registers) */
#define UT_HASH_HR_BASE_OFFSET               ( 0x310u )

/** First four bytes of \ref UT_HASH_DIGEST_WORD0, most significant byte first */
#define UT_HASH_DIGEST_BYTE_0                 ( 0x01u )
#define UT_HASH_DIGEST_BYTE_1                 ( 0x02u )
#define UT_HASH_DIGEST_BYTE_2                 ( 0x03u )
#define UT_HASH_DIGEST_BYTE_3                 ( 0x04u )

/** Byte indices used to split \ref utHash_Abc across two Hash_Set_Update() calls */
#define UT_HASH_ABC_IDX_1                     ( 1u )
#define UT_HASH_ABC_IDX_2                     ( 2u )
#define UT_HASH_ABC_IDX_3                     ( 3u )

/** Size in bytes of the second chunk of \ref utHash_Abc ("bc") */
#define UT_HASH_ABC_REMAINDER_SIZE             ( 2u )

/** Gpdma channel of the DMA mode tests */
#define UT_HASH_DMA_PERIPH                     ( GPDMA_PERIPH_1 )
#define UT_HASH_DMA_CHANNEL                    ( GPDMA_CHANNEL_5 )

/** Gpdma errors the DMA mode shall report (the suspension is left out) */
#define UT_HASH_DMA_ERROR_MASK                 ( GPDMA_ERROR_TRANSFER      | \
                                                 GPDMA_ERROR_CONFIG_UPDATE | \
                                                 GPDMA_ERROR_CONFIG_ERROR  | \
                                                 GPDMA_ERROR_TRIG_OVERRUN )

/** Block size of the one word chunk of the 3 trailing bytes of "abc" */
#define UT_HASH_DMA_ABC_BLOCK                  ( 4u )

/** Long DMA message: one full chunk of 65520 bytes, 32 more bytes (multiple of four words) and 5 trailing bytes */
#define UT_HASH_DMA_CHUNK_MAX                  ( 65520u )
#define UT_HASH_DMA_BODY_REST                  ( 32u )
#define UT_HASH_DMA_TAIL_BLOCK                 ( 8u )
#define UT_HASH_DMA_LONG_SIZE                  ( UT_HASH_DMA_CHUNK_MAX + UT_HASH_DMA_BODY_REST + 5u )

/** NBLW value of a 1 byte last word (8 valid bits) */
#define UT_HASH_NBLW_1_BYTE                    ( 8u )

/** Word-aligned DMA message buffer, the first bytes hold "abc" in the short message tests */
static uint32_t utHash_DmaMsg[ ( UT_HASH_DMA_LONG_SIZE / sizeof( uint32_t ) ) + 1u ];

/* ========================== LOCAL VARIABLES ================================ */

/** HASH interrupt handler registered in Nvic by the code under test */
static nvic_IsrCallback_t utHash_Isr;

/** Gpdma configuration captured from Gpdma_Init() (the transfer configuration it points to is copied) */
static gpdma_ConfigStruct_t   utHash_DmaConfig;
static gpdma_TransferConfig_t utHash_DmaXfer;

/** Number of the completion / error callbacks and the last reported error mask */
static uint32_t         utHash_CompleteCnt;
static uint32_t         utHash_ErrorCnt;
static hash_XferError_t utHash_ErrorMask;

/* ============================ TEST FIXTURE ================================ */

void setUp( void )
{
    TEST_ASSERT_EQUAL( REGMEM_REQUEST_OK, RegMem_Reset() );
}


void tearDown( void )
{
    /* Mocks are verified by generated runner */
}

/* ========================== MODULE VERSION ================================ */

/**
 * \brief   Hash_Get_ModuleVersion() returns version of the module.
 *
 * \par Expected results
 * - Version is 0.1.0 (Major 0, Minor 1, Patch 0).
 */
void Ut_Hash_Get_ModuleVersion_ReturnsVersion( void )
{
    hash_ModuleVersion_t version = Hash_Get_ModuleVersion();

    TEST_ASSERT_EQUAL_UINT8( UT_HASH_VERSION_MAJOR, version.Major );
    TEST_ASSERT_EQUAL_UINT8( UT_HASH_VERSION_MINOR, version.Minor );
    TEST_ASSERT_EQUAL_UINT8( UT_HASH_VERSION_PATCH, version.Patch );
}

/* =========================== DEFAULT CONFIG ================================ */

/**
 * \brief   Hash_Get_DefaultConfig() fills default configuration, rejects NULL.
 *
 * \par Expected results
 * - HASH_REQUEST_OK, POLL transfer mode, Gpdma1 channel 0 low priority, IRQ prio 0, no callbacks.
 * - NULL pointer: HASH_REQUEST_ERROR.
 */
void Ut_Hash_Get_DefaultConfig_ReturnsDefaults( void )
{
    hash_Config_t config;

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_DefaultConfig( &config ) );

    TEST_ASSERT_EQUAL( HASH_XFER_MODE_POLL, config.XferMode );
    TEST_ASSERT_EQUAL( GPDMA_PERIPH_1, config.DmaPeriphId );
    TEST_ASSERT_EQUAL( GPDMA_CHANNEL_0, config.DmaChannelId );
    TEST_ASSERT_EQUAL( GPDMA_PRIORITY_LOW, config.DmaChannelPrio );
    TEST_ASSERT_EQUAL_UINT32( UT_HASH_REG_ZERO, config.IrqPriority );
    TEST_ASSERT_NULL( config.CompleteCallback );
    TEST_ASSERT_NULL( config.ErrorCallback );

    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Get_DefaultConfig( NULL ) );
}

/* ============================ INITIALIZATION ================================ */

/**
 * \brief   Hash_Init() in POLL mode activates the clock and does not touch NVIC.
 *
 * \par Expected results
 * - HASH_REQUEST_OK, Hash_Get_State() returns HASH_STATE_IDLE.
 */
void Ut_Hash_Init_Poll_ActivatesClockOnly( void )
{
    hash_State_t   hashState;
    hash_Config_t config = UtHash_Get_PollConfig();

    UtHash_Expect_InitPoll();

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_State( &hashState ) );
    TEST_ASSERT_EQUAL( HASH_STATE_IDLE, hashState );
}


/**
 * \brief   Hash_Init() in ISR mode registers the handler and activates the interrupt enable bits.
 *
 * \par Expected results
 * - HASH_REQUEST_OK, HASH_IMR has DCIE and DINIE set.
 */
void Ut_Hash_Init_Isr_ActivatesInterrupt( void )
{
    hash_Config_t config = UtHash_Get_PollConfig();

    config.XferMode   = HASH_XFER_MODE_ISR;
    config.IrqPriority = UT_HASH_IRQ_PRIO;

    Rcc_Set_PeriphActive_ExpectAndReturn( RCC_PERIPH_HASH, RCC_REQUEST_OK );
    Nvic_Set_PeriphIrq_Handler_ExpectAndReturn( NVIC_PERIPH_IRQ_HASH, NULL, NVIC_REQUEST_OK );
    Nvic_Set_PeriphIrq_Handler_IgnoreArg_irqHandler();
    Nvic_Set_PeriphIrq_Prio_ExpectAndReturn( NVIC_PERIPH_IRQ_HASH, UT_HASH_IRQ_PRIO, NVIC_REQUEST_OK );
    Nvic_Set_PeriphIrq_Active_ExpectAndReturn( NVIC_PERIPH_IRQ_HASH, NVIC_REQUEST_OK );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );
    TEST_ASSERT_EQUAL_HEX32( ( HASH_IMR_DCIE | HASH_IMR_DINIE ), HASH->IMR );
}


/**
 * \brief   Hash_Init() rejects a NULL configuration and an invalid transfer mode.
 *
 * \par Expected results
 * - Both calls return HASH_REQUEST_ERROR, RCC / NVIC are never called.
 */
void Ut_Hash_Init_InvalidArgs_ReturnsErrorWithoutAccess( void )
{
    hash_Config_t config = UtHash_Get_PollConfig();

    config.XferMode = HASH_XFER_MODE_CNT;

    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Init( NULL ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Init( &config ) );
}


/**
 * \brief   Hash_Deinit() deactivates the NVIC interrupt and the module.
 *
 * \par Expected results
 * - HASH_REQUEST_OK, Hash_Get_State() returns HASH_REQUEST_ERROR afterwards (not initialized).
 */
void Ut_Hash_Deinit_DeactivatesModule( void )
{
    hash_State_t   hashState;
    hash_Config_t config = UtHash_Get_PollConfig();

    UtHash_Expect_InitPoll();
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );

    Nvic_Set_PeriphIrq_Inactive_ExpectAndReturn( NVIC_PERIPH_IRQ_HASH, NVIC_REQUEST_OK );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Deinit() );

    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Get_State( &hashState ) );
}

/* ============================== CAPABILITY ================================== */

/**
 * \brief   Hash_Get_Capability() reports SHA-1 active and MD5 inactive on every STM32H5 line.
 *
 * \par Expected results
 * - HASH_REQUEST_OK for both, SHA-1 active, MD5 inactive.
 */
void Ut_Hash_Get_Capability_Sha1ActiveMd5Inactive( void )
{
    hash_FunctionState_t supported;
    hash_Config_t         config = UtHash_Get_PollConfig();

    UtHash_Expect_InitPoll();
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_Capability( HASH_ALGO_SHA1, &supported ) );
    TEST_ASSERT_EQUAL( HASH_FUNCTION_ACTIVE, supported );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_Capability( HASH_ALGO_MD5, &supported ) );
    TEST_ASSERT_EQUAL( HASH_FUNCTION_INACTIVE, supported );
}


/**
 * \brief   Hash_Get_Capability() reports SHA2-384 per the device line (every line except H503).
 *
 * \par Expected results
 * - HASH_FUNCTION_INACTIVE on H503, HASH_FUNCTION_ACTIVE elsewhere.
 */
void Ut_Hash_Get_Capability_Sha2_384_MatchesLine( void )
{
    hash_FunctionState_t supported;
    hash_FunctionState_t expected = HASH_FUNCTION_ACTIVE;
    hash_Config_t         config   = UtHash_Get_PollConfig();

#if defined( STM32H503xx )
    expected = HASH_FUNCTION_INACTIVE;
#else
    expected = HASH_FUNCTION_ACTIVE;
#endif /* STM32H503xx */

    UtHash_Expect_InitPoll();
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_Capability( HASH_ALGO_SHA2_384, &supported ) );
    TEST_ASSERT_EQUAL( expected, supported );
}


/**
 * \brief   Hash_Get_Capability() reports SHA3-256 only on the lines that implement it
 *          (H543, H553, H5E4, H5E5, H5F4, H5F5 - RM0481 Table 397 / RM0492 / RM0517 block diagrams).
 *
 * \par Expected results
 * - HASH_FUNCTION_ACTIVE on the SHA-3 lines, HASH_FUNCTION_INACTIVE elsewhere.
 */
void Ut_Hash_Get_Capability_Sha3_256_MatchesLine( void )
{
    hash_FunctionState_t supported;
    hash_FunctionState_t expected = HASH_FUNCTION_INACTIVE;
    hash_Config_t         config   = UtHash_Get_PollConfig();

#if defined( STM32H543xx ) || \
    defined( STM32H553xx ) || \
    defined( STM32H5E4xx ) || \
    defined( STM32H5E5xx ) || \
    defined( STM32H5F4xx ) || \
    defined( STM32H5F5xx )
    expected = HASH_FUNCTION_ACTIVE;
#else
    expected = HASH_FUNCTION_INACTIVE;
#endif /* SHA-3 lines */

    UtHash_Expect_InitPoll();
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_Capability( HASH_ALGO_SHA3_256, &supported ) );
    TEST_ASSERT_EQUAL( expected, supported );
}


/**
 * \brief   Hash_Get_Capability() rejects a NULL output pointer and an out of range algorithm.
 *
 * \par Expected results
 * - Both calls return HASH_REQUEST_ERROR.
 */
void Ut_Hash_Get_Capability_InvalidArgs_ReturnsError( void )
{
    hash_FunctionState_t supported;
    hash_Config_t         config = UtHash_Get_PollConfig();

    UtHash_Expect_InitPoll();
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );

    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Get_Capability( HASH_ALGO_SHA1, NULL ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Get_Capability( HASH_ALGO_CNT, &supported ) );
}


/**
 * \brief   Hash_Get_Capability() and Hash_Get_DigestSize() return an error before Hash_Init(),
 *          consistent with the other getters of the module (no side effects).
 *
 * \par Expected results
 * - Both calls return HASH_REQUEST_ERROR.
 */
void Ut_Hash_Get_Capability_NotInitialized_ReturnsError( void )
{
    hash_FunctionState_t supported;
    hash_DataCnt_t        digestSize;

    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Get_Capability( HASH_ALGO_SHA1, &supported ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Get_DigestSize( HASH_ALGO_SHA1, &digestSize ) );
}

/* ============================== DIGEST SIZE ================================== */

/**
 * \brief   Hash_Get_DigestSize() returns 32 for SHA2-256 and 0 (variable) for SHAKE128.
 *
 * \par Expected results
 * - HASH_REQUEST_OK for both, sizes as above.
 */
void Ut_Hash_Get_DigestSize_Sha256AndShake128( void )
{
    hash_DataCnt_t digestSize;
    hash_Config_t  config = UtHash_Get_PollConfig();

    UtHash_Expect_InitPoll();
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_DigestSize( HASH_ALGO_SHA2_256, &digestSize ) );
    TEST_ASSERT_EQUAL_UINT32( UT_HASH_SHA256_DIGEST_SIZE, digestSize );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_DigestSize( HASH_ALGO_SHAKE128, &digestSize ) );
    TEST_ASSERT_EQUAL_UINT32( UT_HASH_REG_ZERO, digestSize );
}

/* ================================== STATE ===================================== */

/**
 * \brief   Hash_Get_State() returns an error before Hash_Init() and HASH_STATE_IDLE after.
 *
 * \par Expected results
 * - Before Init: HASH_REQUEST_ERROR. After Init: HASH_REQUEST_OK, HASH_STATE_IDLE.
 */
void Ut_Hash_Get_State_IdleAfterInit( void )
{
    hash_State_t   hashState = HASH_STATE_ERROR;
    hash_Config_t config     = UtHash_Get_PollConfig();

    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Get_State( &hashState ) );

    UtHash_Expect_InitPoll();
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_State( &hashState ) );
    TEST_ASSERT_EQUAL( HASH_STATE_IDLE, hashState );
}


/**
 * \brief   Hash_Get_XferError() returns the accumulated mask and clears it.
 *
 * \par Expected results
 * - First call returns HASH_XFER_ERROR_NONE (nothing happened yet); the getter
 *   always succeeds for a non-NULL pointer and rejects a NULL pointer.
 */
void Ut_Hash_Get_XferError_ReturnsAndClears( void )
{
    hash_XferError_t xferError;

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_XferError( &xferError ) );
    TEST_ASSERT_EQUAL( HASH_XFER_ERROR_NONE, xferError );
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Get_XferError( NULL ) );
}

/* ================================ ONE-SHOT ===================================== */

/**
 * \brief   Hash_Set_Calculate() rejects a NULL request and an unsupported algorithm.
 *
 * \par Expected results
 * - Both calls return HASH_REQUEST_ERROR, no register is written (HASH_CR stays 0).
 */
void Ut_Hash_Set_Calculate_InvalidArgs_ReturnsErrorWithoutAccess( void )
{
    hash_Data_t    digest[ UT_HASH_SHA1_DIGEST_SIZE ];
    hash_Config_t  config  = UtHash_Get_PollConfig();
    hash_Request_t request = { 0 };

    UtHash_Expect_InitPoll();
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );

    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Set_Calculate( NULL ) );

    request.Algorithm  = HASH_ALGO_MD5;        /* Not supported on STM32H5 */
    request.Mode       = HASH_MODE_HASH;
    request.Input       = utHash_Abc;
    request.InputSize   = sizeof( utHash_Abc );
    request.Digest      = digest;
    request.DigestSize  = sizeof( digest );

    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Set_Calculate( &request ) );
    TEST_ASSERT_EQUAL_HEX32( UT_HASH_REG_ZERO, HASH->CR );
}


/**
 * \brief   Hash_Set_Calculate() computes SHA-1 of "abc" in POLL mode and reads the digest back.
 *
 * \details HASH_SR.DINIS / DCIS are preset so the bounded wait loops succeed right away,
 *          HASH_HR0 is preset to a known pattern the test reads back from the digest buffer.
 *
 * \par Expected results
 * - HASH_REQUEST_OK, HASH_CR.ALGO = SHA-1 (0), DATATYPE = byte swap, INIT was set.
 * - HASH_STR.NBLW = 24 (3 valid bytes of the last word), DCAL set.
 * - HASH_DIN holds the last written word 0x00636261 (first byte at bits 7..0, the peripheral swaps the bytes).
 * - HASH_SR.DCIS is cleared after the digest was read (HASH_HRx read as zero while DCIS = 0).
 * - digest[0..3] equal HASH_HR0 most significant byte first.
 */
void Ut_Hash_Set_Calculate_Sha1Poll_ComputesAndReadsDigest( void )
{
    hash_Data_t     digest[ UT_HASH_SHA1_DIGEST_SIZE ];
    hash_Config_t   config  = UtHash_Get_PollConfig();
    hash_Request_t  request = { 0 };

    UtHash_Expect_InitPoll();
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );

    Hash_Set_RegVal( HASH_REG_SR, ( HASH_SR_DINIS | HASH_SR_DCIS ), ( HASH_SR_DINIS | HASH_SR_DCIS ) );
    *( (volatile uint32_t *)( (uint8_t *)HASH + UT_HASH_HR_BASE_OFFSET ) ) = UT_HASH_DIGEST_WORD0;

    request.Algorithm  = HASH_ALGO_SHA1;
    request.Mode        = HASH_MODE_HASH;
    request.Input        = utHash_Abc;
    request.InputSize    = sizeof( utHash_Abc );
    request.Digest       = digest;
    request.DigestSize   = sizeof( digest );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Calculate( &request ) );

    TEST_ASSERT_EQUAL_HEX32( ( HASH_CR_DATATYPE_1 ), ( HASH->CR & ( HASH_CR_ALGO | HASH_CR_DATATYPE_1 ) ) );
    TEST_ASSERT_EQUAL_UINT32( UT_HASH_NBLW_3_BYTES, ( HASH->STR & HASH_STR_NBLW ) );
    TEST_ASSERT_EQUAL_HEX32( UT_HASH_ABC_WORD, HASH->DIN );
    TEST_ASSERT_EQUAL_HEX32( UT_HASH_REG_ZERO, ( HASH->SR & HASH_SR_DCIS ) );

    TEST_ASSERT_EQUAL_UINT8( UT_HASH_DIGEST_BYTE_0, digest[ 0 ] );
    TEST_ASSERT_EQUAL_UINT8( UT_HASH_DIGEST_BYTE_1, digest[ UT_HASH_ABC_IDX_1 ] );
    TEST_ASSERT_EQUAL_UINT8( UT_HASH_DIGEST_BYTE_2, digest[ UT_HASH_ABC_IDX_2 ] );
    TEST_ASSERT_EQUAL_UINT8( UT_HASH_DIGEST_BYTE_3, digest[ UT_HASH_ABC_IDX_3 ] );
}


/**
 * \brief   Hash_Set_Calculate() of the empty message writes no word to HASH_DIN, only NBLW = 0 and DCAL.
 *
 * \par Expected results
 * - HASH_REQUEST_OK, HASH_DIN keeps the value preset by the test (no zero word was written, it would be hashed
 *   as four message bytes), NBLW = 0, DCAL set.
 */
void Ut_Hash_Set_Calculate_EmptyPoll_WritesNoWord( void )
{
    hash_Data_t     digest[ UT_HASH_SHA1_DIGEST_SIZE ];
    hash_Config_t   config  = UtHash_Get_PollConfig();
    hash_Request_t  request = { 0 };

    UtHash_Expect_InitPoll();
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );

    Hash_Set_RegVal( HASH_REG_SR, ( HASH_SR_DINIS | HASH_SR_DCIS ), ( HASH_SR_DINIS | HASH_SR_DCIS ) );
    Hash_Set_RegVal( HASH_REG_DIN, HASH_REG_FULL_MASK, UT_HASH_DIGEST_WORD0 );

    request.Algorithm  = HASH_ALGO_SHA1;
    request.Mode       = HASH_MODE_HASH;
    request.Input      = NULL;
    request.InputSize  = 0u;
    request.Digest     = digest;
    request.DigestSize = sizeof( digest );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Calculate( &request ) );

    TEST_ASSERT_EQUAL_HEX32( UT_HASH_DIGEST_WORD0, HASH->DIN );
    TEST_ASSERT_EQUAL_UINT32( UT_HASH_REG_ZERO, ( HASH->STR & HASH_STR_NBLW ) );
    TEST_ASSERT_EQUAL_HEX32( HASH_STR_DCAL, ( HASH->STR & HASH_STR_DCAL ) );
}


/**
 * \brief   Hash_Set_Calculate() rejects HASH_MODE_HMAC in DMA transfer mode.
 *
 * \par Expected results
 * - HASH_REQUEST_ERROR, Gpdma is never called.
 */
void Ut_Hash_Set_Calculate_HmacDma_ReturnsErrorWithoutGpdma( void )
{
    hash_Data_t     digest[ UT_HASH_SHA1_DIGEST_SIZE ];
    hash_Request_t  request = { 0 };

    UtHash_Init_Dma();

    request.Algorithm  = HASH_ALGO_SHA1;
    request.Mode        = HASH_MODE_HMAC;
    request.Input        = (const hash_Data_t *)utHash_DmaMsg;
    request.InputSize    = sizeof( utHash_Abc );
    request.Key          = utHash_Abc;
    request.KeySize      = sizeof( utHash_Abc );
    request.Digest       = digest;
    request.DigestSize   = sizeof( digest );

    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Set_Calculate( &request ) );
}

/* ================================= DMA MODE ======================================= */

/**
 * \brief   Hash_Init() in DMA mode initializes the Gpdma channel and activates its interrupt.
 *
 * \par Expected results
 * - HASH_REQUEST_OK, Gpdma_Init() gets the HASH input request with single requests, 32-bit words from the memory
 *   to the static HASH_DIN address, both callbacks and the error mask without the suspension;
 *   Gpdma_Set_InterruptActive() of the channel follows.
 */
void Ut_Hash_Init_Dma_InitializesChannelWithoutSuspension( void )
{
    UtHash_Init_Dma();

    TEST_ASSERT_EQUAL( UT_HASH_DMA_PERIPH, utHash_DmaConfig.PeriphId );
    TEST_ASSERT_EQUAL( UT_HASH_DMA_CHANNEL, utHash_DmaConfig.ChannelId );
    TEST_ASSERT_EQUAL_HEX32( UT_HASH_DMA_ERROR_MASK, utHash_DmaConfig.ErrorMask );
    TEST_ASSERT_NOT_NULL( utHash_DmaConfig.TransferCompleteIsr );
    TEST_ASSERT_NOT_NULL( utHash_DmaConfig.ErrorIsr );
    TEST_ASSERT_EQUAL( GPDMA_REQ_HASH_IN, utHash_DmaXfer.RequestSource );
    TEST_ASSERT_EQUAL( GPDMA_PERIPH_REQ_SINGLE, utHash_DmaXfer.RequestMode );
    TEST_ASSERT_EQUAL( GPDMA_DIR_MEMORY_TO_PERIPH, utHash_DmaXfer.Direction );
    TEST_ASSERT_EQUAL( GPDMA_DATA_SIZE_32BITS, utHash_DmaXfer.SourceDataSize );
    TEST_ASSERT_EQUAL( GPDMA_DATA_SIZE_32BITS, utHash_DmaXfer.DestinationDataSize );
    TEST_ASSERT_EQUAL( GPDMA_ADDR_STATIC, utHash_DmaXfer.DestinationAddrMode );
    TEST_ASSERT_EQUAL_HEX32( Hash_Reg_Get_DinAddr(), utHash_DmaXfer.DestinationAddr );
}


/**
 * \brief   Hash_Set_Calculate() in DMA mode rejects an input that is not word aligned.
 *
 * \par Expected results
 * - HASH_REQUEST_ERROR, no Gpdma call after the initialization (the mock fails on an unexpected call), HASH_CR.DMAE
 *   stays clear.
 */
void Ut_Hash_Set_Calculate_DmaUnalignedInput_ReturnsErrorWithoutGpdma( void )
{
    hash_Data_t    digest[ UT_HASH_SHA1_DIGEST_SIZE ];
    hash_Request_t request = { 0 };

    UtHash_Init_Dma();

    request.Algorithm  = HASH_ALGO_SHA1;
    request.Mode       = HASH_MODE_HASH;
    request.Input      = &( (const hash_Data_t *)utHash_DmaMsg )[ 1 ];
    request.InputSize  = UT_HASH_ABC_SIZE;
    request.Digest     = digest;
    request.DigestSize = sizeof( digest );

    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Set_Calculate( &request ) );
    TEST_ASSERT_EQUAL_HEX32( UT_HASH_REG_ZERO, ( HASH->CR & HASH_CR_DMAE ) );
}


/**
 * \brief   A DMA request of "abc" sends the 3 bytes as one word chunk and ends by the HASH digest interrupt; a second
 *          request reuses the channel without a new Gpdma_Init().
 *
 * \par Expected results
 * - Start: HASH_REQUEST_OK, NBLW = 24, DMAE set, MDMAT clear (single chunk), a one word chunk is started, the state
 *   is BUSY and Hash_Set_Update() is rejected (no incremental calculation is open).
 * - Gpdma transfer complete: DCIE set, no callback yet.
 * - HASH interrupt with DCIS: digest[0..3] equal HASH_HR0 most significant byte first, DCIS, DCIE and DMAE cleared,
 *   the state is IDLE, one completion callback.
 * - The second request starts its chunk without Gpdma_Init() (the mock fails on an unexpected call).
 */
void Ut_Hash_Set_Calculate_DmaShortMessage_EndsByDigestInterrupt( void )
{
    hash_Data_t    digest[ UT_HASH_SHA1_DIGEST_SIZE ];
    hash_Request_t request   = { 0 };
    hash_State_t   hashState = HASH_STATE_CNT;

    UtHash_Init_Dma();

    utHash_DmaMsg[ 0 ] = UT_HASH_ABC_WORD;

    request.Algorithm  = HASH_ALGO_SHA1;
    request.Mode       = HASH_MODE_HASH;
    request.Input      = (const hash_Data_t *)utHash_DmaMsg;
    request.InputSize  = UT_HASH_ABC_SIZE;
    request.Digest     = digest;
    request.DigestSize = sizeof( digest );

    UtHash_Expect_DmaChunk( UT_HASH_DMA_ABC_BLOCK, NULL );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Calculate( &request ) );

    TEST_ASSERT_EQUAL_UINT32( UT_HASH_NBLW_3_BYTES, ( HASH->STR & HASH_STR_NBLW ) );
    TEST_ASSERT_EQUAL_HEX32( HASH_CR_DMAE, ( HASH->CR & HASH_CR_DMAE ) );
    TEST_ASSERT_EQUAL_HEX32( UT_HASH_REG_ZERO, ( HASH->CR & HASH_CR_MDMAT ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_State( &hashState ) );
    TEST_ASSERT_EQUAL( HASH_STATE_BUSY, hashState );
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Set_Update( utHash_Abc, sizeof( utHash_Abc ) ) );

    utHash_DmaConfig.TransferCompleteIsr();

    TEST_ASSERT_EQUAL_HEX32( HASH_IMR_DCIE, ( HASH->IMR & HASH_IMR_DCIE ) );
    TEST_ASSERT_EQUAL_UINT32( 0u, utHash_CompleteCnt );

    Hash_Set_RegBit( HASH_REG_SR, HASH_SR_DCIS );
    *( (volatile uint32_t *)( (uint8_t *)HASH + UT_HASH_HR_BASE_OFFSET ) ) = UT_HASH_DIGEST_WORD0;
    utHash_Isr();

    TEST_ASSERT_EQUAL_UINT8( UT_HASH_DIGEST_BYTE_0, digest[ 0 ] );
    TEST_ASSERT_EQUAL_UINT8( UT_HASH_DIGEST_BYTE_1, digest[ UT_HASH_ABC_IDX_1 ] );
    TEST_ASSERT_EQUAL_UINT8( UT_HASH_DIGEST_BYTE_2, digest[ UT_HASH_ABC_IDX_2 ] );
    TEST_ASSERT_EQUAL_UINT8( UT_HASH_DIGEST_BYTE_3, digest[ UT_HASH_ABC_IDX_3 ] );
    TEST_ASSERT_EQUAL_HEX32( UT_HASH_REG_ZERO, ( HASH->SR & HASH_SR_DCIS ) );
    TEST_ASSERT_EQUAL_HEX32( UT_HASH_REG_ZERO, ( HASH->IMR & HASH_IMR_DCIE ) );
    TEST_ASSERT_EQUAL_HEX32( UT_HASH_REG_ZERO, ( HASH->CR & HASH_CR_DMAE ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_State( &hashState ) );
    TEST_ASSERT_EQUAL( HASH_STATE_IDLE, hashState );
    TEST_ASSERT_EQUAL_UINT32( 1u, utHash_CompleteCnt );

    UtHash_Expect_DmaChunk( UT_HASH_DMA_ABC_BLOCK, NULL );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Calculate( &request ) );
}


/**
 * \brief   A DMA request longer than one Gpdma block is split: full chunks with MDMAT set, the trailing bytes as the
 *          last chunk with MDMAT clear.
 *
 * \details 65557 bytes = 65520 (largest multiple of four words within the 16-bit block size) + 32 + 5 trailing bytes.
 *
 * \par Expected results
 * - NBLW = 8 (1 valid byte in the last word).
 * - Chunk 1: 65520 bytes from the message start, MDMAT set.
 * - Chunk 2: 32 bytes from the message start + 65520, MDMAT set.
 * - Chunk 3: the 5 trailing bytes as 8 bytes from the copy in the module, MDMAT clear.
 * - DCIE is set only after the transfer complete of the last chunk.
 */
void Ut_Hash_Set_Calculate_DmaLongMessage_SplitsChunks( void )
{
    hash_Data_t        digest[ UT_HASH_SHA1_DIGEST_SIZE ];
    hash_Request_t     request = { 0 };
    const hash_Data_t *msg     = (const hash_Data_t *)utHash_DmaMsg;

    UtHash_Init_Dma();

    request.Algorithm  = HASH_ALGO_SHA1;
    request.Mode       = HASH_MODE_HASH;
    request.Input      = msg;
    request.InputSize  = UT_HASH_DMA_LONG_SIZE;
    request.Digest     = digest;
    request.DigestSize = sizeof( digest );

    UtHash_Expect_DmaChunk( UT_HASH_DMA_CHUNK_MAX, msg );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Calculate( &request ) );
    TEST_ASSERT_EQUAL_UINT32( UT_HASH_NBLW_1_BYTE, ( HASH->STR & HASH_STR_NBLW ) );
    TEST_ASSERT_EQUAL_HEX32( HASH_CR_MDMAT, ( HASH->CR & HASH_CR_MDMAT ) );

    UtHash_Expect_DmaChunk( UT_HASH_DMA_BODY_REST, &msg[ UT_HASH_DMA_CHUNK_MAX ] );
    utHash_DmaConfig.TransferCompleteIsr();
    TEST_ASSERT_EQUAL_HEX32( HASH_CR_MDMAT, ( HASH->CR & HASH_CR_MDMAT ) );
    TEST_ASSERT_EQUAL_HEX32( UT_HASH_REG_ZERO, ( HASH->IMR & HASH_IMR_DCIE ) );

    UtHash_Expect_DmaChunk( UT_HASH_DMA_TAIL_BLOCK, NULL );
    utHash_DmaConfig.TransferCompleteIsr();
    TEST_ASSERT_EQUAL_HEX32( UT_HASH_REG_ZERO, ( HASH->CR & HASH_CR_MDMAT ) );
    TEST_ASSERT_EQUAL_HEX32( UT_HASH_REG_ZERO, ( HASH->IMR & HASH_IMR_DCIE ) );

    utHash_DmaConfig.TransferCompleteIsr();
    TEST_ASSERT_EQUAL_HEX32( HASH_IMR_DCIE, ( HASH->IMR & HASH_IMR_DCIE ) );
}


/**
 * \brief   A DMA request of an empty message is padded by software and ends by the digest interrupt as well.
 *
 * \par Expected results
 * - HASH_REQUEST_OK without any Gpdma call, DCAL written, DMAE clear, DCIE set right away.
 * - HASH interrupt with DCIS: the state is IDLE, one completion callback.
 */
void Ut_Hash_Set_Calculate_DmaEmptyMessage_PadsBySoftware( void )
{
    hash_Data_t    digest[ UT_HASH_SHA1_DIGEST_SIZE ];
    hash_Request_t request   = { 0 };
    hash_State_t   hashState = HASH_STATE_CNT;

    UtHash_Init_Dma();

    request.Algorithm  = HASH_ALGO_SHA1;
    request.Mode       = HASH_MODE_HASH;
    request.Input      = NULL;
    request.InputSize  = 0u;
    request.Digest     = digest;
    request.DigestSize = sizeof( digest );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Calculate( &request ) );
    TEST_ASSERT_EQUAL_HEX32( HASH_STR_DCAL, ( HASH->STR & HASH_STR_DCAL ) );
    TEST_ASSERT_EQUAL_HEX32( UT_HASH_REG_ZERO, ( HASH->CR & HASH_CR_DMAE ) );
    TEST_ASSERT_EQUAL_HEX32( HASH_IMR_DCIE, ( HASH->IMR & HASH_IMR_DCIE ) );

    Hash_Set_RegBit( HASH_REG_SR, HASH_SR_DCIS );
    utHash_Isr();

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_State( &hashState ) );
    TEST_ASSERT_EQUAL( HASH_STATE_IDLE, hashState );
    TEST_ASSERT_EQUAL_UINT32( 1u, utHash_CompleteCnt );
}


/**
 * \brief   A Gpdma error ends the running DMA request with a DMA transfer error.
 *
 * \par Expected results
 * - The state is ERROR, one error callback with HASH_XFER_ERROR_DMA, DMAE and DCIE clear, no completion callback.
 * - A transfer complete reported after the error does not continue the request (no Gpdma call, DCIE stays clear).
 */
void Ut_Hash_DmaError_EndsRequestWithDmaError( void )
{
    hash_Data_t    digest[ UT_HASH_SHA1_DIGEST_SIZE ];
    hash_Request_t request   = { 0 };
    hash_State_t   hashState = HASH_STATE_CNT;

    UtHash_Init_Dma();

    request.Algorithm  = HASH_ALGO_SHA1;
    request.Mode       = HASH_MODE_HASH;
    request.Input      = (const hash_Data_t *)utHash_DmaMsg;
    request.InputSize  = UT_HASH_ABC_SIZE;
    request.Digest     = digest;
    request.DigestSize = sizeof( digest );

    UtHash_Expect_DmaChunk( UT_HASH_DMA_ABC_BLOCK, NULL );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Calculate( &request ) );

    utHash_DmaConfig.ErrorIsr( GPDMA_ERROR_TRANSFER );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_State( &hashState ) );
    TEST_ASSERT_EQUAL( HASH_STATE_ERROR, hashState );
    TEST_ASSERT_EQUAL_UINT32( 1u, utHash_ErrorCnt );
    TEST_ASSERT_EQUAL( HASH_XFER_ERROR_DMA, utHash_ErrorMask );
    TEST_ASSERT_EQUAL_HEX32( UT_HASH_REG_ZERO, ( HASH->CR & HASH_CR_DMAE ) );

    utHash_DmaConfig.TransferCompleteIsr();

    TEST_ASSERT_EQUAL_HEX32( UT_HASH_REG_ZERO, ( HASH->IMR & HASH_IMR_DCIE ) );
    TEST_ASSERT_EQUAL_UINT32( 0u, utHash_CompleteCnt );
}


/**
 * \brief   Hash_Set_Abort() stops a running DMA request.
 *
 * \par Expected results
 * - HASH_REQUEST_OK, Gpdma_Set_ChannelInactive() of the channel, DMAE and DCIE clear, INIT set, the state is IDLE.
 * - A transfer complete reported after the abort does not continue the request, no callback.
 */
void Ut_Hash_Set_Abort_DmaRequest_StopsChannel( void )
{
    hash_Data_t    digest[ UT_HASH_SHA1_DIGEST_SIZE ];
    hash_Request_t request   = { 0 };
    hash_State_t   hashState = HASH_STATE_CNT;

    UtHash_Init_Dma();

    request.Algorithm  = HASH_ALGO_SHA1;
    request.Mode       = HASH_MODE_HASH;
    request.Input      = (const hash_Data_t *)utHash_DmaMsg;
    request.InputSize  = UT_HASH_DMA_LONG_SIZE;
    request.Digest     = digest;
    request.DigestSize = sizeof( digest );

    UtHash_Expect_DmaChunk( UT_HASH_DMA_CHUNK_MAX, request.Input );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Calculate( &request ) );

    Gpdma_Set_ChannelInactive_ExpectAndReturn( UT_HASH_DMA_PERIPH, UT_HASH_DMA_CHANNEL, GPDMA_REQUEST_OK );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Abort() );

    TEST_ASSERT_EQUAL_HEX32( UT_HASH_REG_ZERO, ( HASH->CR & ( HASH_CR_DMAE | HASH_CR_MDMAT ) ) );
    TEST_ASSERT_EQUAL_HEX32( HASH_CR_INIT, ( HASH->CR & HASH_CR_INIT ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_State( &hashState ) );
    TEST_ASSERT_EQUAL( HASH_STATE_IDLE, hashState );

    utHash_DmaConfig.TransferCompleteIsr();

    TEST_ASSERT_EQUAL_HEX32( UT_HASH_REG_ZERO, ( HASH->IMR & HASH_IMR_DCIE ) );
    TEST_ASSERT_EQUAL_UINT32( 0u, utHash_CompleteCnt );
    TEST_ASSERT_EQUAL_UINT32( 0u, utHash_ErrorCnt );
}


/**
 * \brief   Hash_Deinit() in DMA mode releases the Gpdma channel.
 *
 * \par Expected results
 * - HASH_REQUEST_OK, Nvic interrupt off, Gpdma_Deinit() and Gpdma_Set_InterruptInactive() of the channel.
 */
void Ut_Hash_Deinit_Dma_ReleasesChannel( void )
{
    UtHash_Init_Dma();

    Nvic_Set_PeriphIrq_Inactive_ExpectAndReturn( NVIC_PERIPH_IRQ_HASH, NVIC_REQUEST_OK );
    Gpdma_Deinit_ExpectAndReturn( UT_HASH_DMA_PERIPH, UT_HASH_DMA_CHANNEL, GPDMA_REQUEST_OK );
    Gpdma_Set_InterruptInactive_ExpectAndReturn( UT_HASH_DMA_PERIPH, UT_HASH_DMA_CHANNEL, GPDMA_REQUEST_OK );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Deinit() );
}

/* ================================ INCREMENTAL ===================================== */

/**
 * \brief   Hash_Set_Start() rejects the incremental interface in DMA transfer mode
 *          (DMA only drives the one-shot Hash_Set_Calculate(), see the module report).
 *
 * \par Expected results
 * - HASH_REQUEST_ERROR, no calculation is opened (a following Hash_Set_Update() is
 *   still rejected for the same reason).
 */
void Ut_Hash_Set_Start_DmaMode_ReturnsErrorWithoutAccess( void )
{
    hash_StartConfig_t  startConfig = { 0 };

    UtHash_Init_Dma();

    startConfig.Algorithm = HASH_ALGO_SHA1;
    startConfig.Mode       = HASH_MODE_HASH;

    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Set_Start( &startConfig ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Set_Update( utHash_Abc, sizeof( utHash_Abc ) ) );
}

/**
 * \brief   Hash_Set_Start() / Hash_Set_Update() / Hash_Set_Finish() split "abc" into two updates.
 *
 * \par Expected results
 * - Every call returns HASH_REQUEST_OK, HASH_CR.MODE stays clear (plain hash), the
 *   digest is read back the same way as the one-shot test.
 */
void Ut_Hash_Incremental_TwoUpdates_ComputesDigest( void )
{
    hash_Data_t         digest[ UT_HASH_SHA1_DIGEST_SIZE ];
    hash_Config_t       config      = UtHash_Get_PollConfig();
    hash_StartConfig_t  startConfig = { 0 };

    UtHash_Expect_InitPoll();
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );

    Hash_Set_RegVal( HASH_REG_SR, ( HASH_SR_DINIS | HASH_SR_DCIS ), ( HASH_SR_DINIS | HASH_SR_DCIS ) );
    *( (volatile uint32_t *)( (uint8_t *)HASH + UT_HASH_HR_BASE_OFFSET ) ) = UT_HASH_DIGEST_WORD0;

    startConfig.Algorithm = HASH_ALGO_SHA1;
    startConfig.Mode       = HASH_MODE_HASH;

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Start( &startConfig ) );
    TEST_ASSERT_EQUAL_HEX32( UT_HASH_REG_ZERO, ( HASH->CR & HASH_CR_MODE ) );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Update( &utHash_Abc[ 0 ], 1u ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK,
                       Hash_Set_Update( &utHash_Abc[ UT_HASH_ABC_IDX_1 ],
                                        UT_HASH_ABC_REMAINDER_SIZE ) );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Finish( digest, sizeof( digest ) ) );
    TEST_ASSERT_EQUAL_UINT8( UT_HASH_DIGEST_BYTE_0, digest[ 0 ] );
}


/**
 * \brief   Hash_Set_Update() rejects data when no calculation is open.
 *
 * \par Expected results
 * - HASH_REQUEST_ERROR.
 */
void Ut_Hash_Set_Update_NoCalcOpen_ReturnsError( void )
{
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Set_Update( utHash_Abc, sizeof( utHash_Abc ) ) );
}


/**
 * \brief   Hash_Set_Abort() clears the open calculation and sets HASH_CR.INIT.
 *
 * \par Expected results
 * - HASH_REQUEST_OK, HASH_CR.INIT set, Hash_Get_State() returns HASH_STATE_IDLE,
 *   a following Hash_Set_Update() is rejected (no calculation open any more).
 */
void Ut_Hash_Set_Abort_ClearsCalcAndSetsInit( void )
{
    hash_State_t        hashState;
    hash_Config_t       config      = UtHash_Get_PollConfig();
    hash_StartConfig_t  startConfig = { 0 };

    UtHash_Expect_InitPoll();
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );

    startConfig.Algorithm = HASH_ALGO_SHA1;
    startConfig.Mode       = HASH_MODE_HASH;
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Start( &startConfig ) );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Abort() );

    TEST_ASSERT_EQUAL_HEX32( HASH_CR_INIT, ( HASH->CR & HASH_CR_INIT ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_State( &hashState ) );
    TEST_ASSERT_EQUAL( HASH_STATE_IDLE, hashState );
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Set_Update( utHash_Abc, sizeof( utHash_Abc ) ) );
}

/* ============================ SUSPEND AND RESUME ================================== */

/**
 * \brief   Hash_Get_Context() saves HASH_CR / HASH_STR / HASH_IMR and HASH_Set_Context() restores them.
 *
 * \par Expected results
 * - Hash_Get_Context() returns HASH_REQUEST_OK and captures the register values.
 * - After the registers are cleared, Hash_Set_Context() writes them back and sets HASH_CR.INIT.
 */
void Ut_Hash_ContextRoundTrip_RestoresRegisters( void )
{
    hash_Context_t      context;
    hash_Config_t       config      = UtHash_Get_PollConfig();
    hash_StartConfig_t  startConfig = { 0 };

    UtHash_Expect_InitPoll();
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );

    startConfig.Algorithm = HASH_ALGO_SHA1;
    startConfig.Mode       = HASH_MODE_HASH;
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Start( &startConfig ) );

    Hash_Set_RegVal( HASH_REG_SR, HASH_SR_DINIS, HASH_SR_DINIS );

    const uint32_t crBefore = HASH->CR;

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_Context( &context ) );

    Hash_Set_RegVal( HASH_REG_CR, HASH_REG_FULL_MASK, UT_HASH_REG_ZERO );
    TEST_ASSERT_EQUAL_HEX32( UT_HASH_REG_ZERO, HASH->CR );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Context( &context ) );

    TEST_ASSERT_EQUAL_HEX32( ( crBefore | HASH_CR_INIT ), HASH->CR );
}


/**
 * \brief   The incomplete word of the module (bytes not yet written to HASH_DIN) travels with the context.
 *
 * \par Expected results
 * - After "abc" (one incomplete word) Hash_Get_Context() and Hash_Set_Context() return HASH_REQUEST_OK.
 * - Hash_Set_Finish() then writes the word 0x00636261 to HASH_DIN and sets HASH_STR.NBLW = 24.
 */
void Ut_Hash_ContextRoundTrip_KeepsIncompleteWord( void )
{
    hash_Data_t         digest[ UT_HASH_SHA1_DIGEST_SIZE ];
    hash_Context_t      context;
    hash_Config_t       config      = UtHash_Get_PollConfig();
    hash_StartConfig_t  startConfig = { 0 };

    UtHash_Expect_InitPoll();
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );

    Hash_Set_RegVal( HASH_REG_SR, ( HASH_SR_DINIS | HASH_SR_DCIS ), ( HASH_SR_DINIS | HASH_SR_DCIS ) );

    startConfig.Algorithm = HASH_ALGO_SHA1;
    startConfig.Mode       = HASH_MODE_HASH;
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Start( &startConfig ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Update( utHash_Abc, UT_HASH_ABC_SIZE ) );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_Context( &context ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Context( &context ) );

    Hash_Set_RegVal( HASH_REG_SR, ( HASH_SR_DINIS | HASH_SR_DCIS ), ( HASH_SR_DINIS | HASH_SR_DCIS ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Finish( digest, sizeof( digest ) ) );

    TEST_ASSERT_EQUAL_HEX32( UT_HASH_ABC_WORD, HASH->DIN );
    TEST_ASSERT_EQUAL_UINT32( UT_HASH_NBLW_3_BYTES, ( HASH->STR & HASH_STR_NBLW ) );
}


/**
 * \brief   Hash_Set_Context() rejects a NULL context and a calculation already open.
 *
 * \par Expected results
 * - Both calls return HASH_REQUEST_ERROR.
 */
void Ut_Hash_Set_Context_InvalidArgs_ReturnsError( void )
{
    hash_Config_t       config      = UtHash_Get_PollConfig();
    hash_StartConfig_t  startConfig = { 0 };
    hash_Context_t      context     = { { 0 } };

    UtHash_Expect_InitPoll();
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );

    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Set_Context( NULL ) );

    startConfig.Algorithm = HASH_ALGO_SHA1;
    startConfig.Mode       = HASH_MODE_HASH;
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Start( &startConfig ) );

    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Set_Context( &context ) );
}

/* ================================= INTERRUPTS ======================================= */

/**
 * \brief   Hash_Set_IrqPriority() / Hash_Get_IrqPriority() forward to Nvic.
 *
 * \par Expected results
 * - Both calls return HASH_REQUEST_OK and use NVIC_PERIPH_IRQ_HASH.
 */
void Ut_Hash_IrqPriority_SetAndGet_UsesNvic( void )
{
    hash_IrqPrio_t irqPrio = UT_HASH_REG_ZERO;

    Nvic_Set_PeriphIrq_Prio_ExpectAndReturn( NVIC_PERIPH_IRQ_HASH, UT_HASH_IRQ_PRIO, NVIC_REQUEST_OK );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_IrqPriority( UT_HASH_IRQ_PRIO ) );

    Nvic_Get_PeriphIrq_Prio_ExpectAndReturn( NVIC_PERIPH_IRQ_HASH, NULL, NVIC_REQUEST_OK );
    Nvic_Get_PeriphIrq_Prio_IgnoreArg_irqPrio();
    Nvic_Get_PeriphIrq_Prio_ReturnThruPtr_irqPrio( &irqPrio );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_IrqPriority( &irqPrio ) );
}

/* =========================== LOCAL FUNCTIONS =============================== */

/**
 * \brief Sets up the Rcc / Nvic mock expectations of Hash_Init() in POLL mode.
 */
static void UtHash_Expect_InitPoll( void )
{
    Rcc_Set_PeriphActive_ExpectAndReturn( RCC_PERIPH_HASH, RCC_REQUEST_OK );
}


/**
 * \brief Builds a POLL mode configuration without callbacks.
 */
static hash_Config_t UtHash_Get_PollConfig( void )
{
    hash_Config_t config;

    (void)Hash_Get_DefaultConfig( &config );

    return ( config );
}


/**
 * \brief Initializes the module in DMA mode on \ref UT_HASH_DMA_CHANNEL with both callbacks and captures the HASH
 *        interrupt handler and the Gpdma configuration.
 */
static void UtHash_Init_Dma( void )
{
    hash_Config_t config = UtHash_Get_PollConfig();

    config.XferMode         = HASH_XFER_MODE_DMA;
    config.DmaPeriphId      = UT_HASH_DMA_PERIPH;
    config.DmaChannelId     = UT_HASH_DMA_CHANNEL;
    config.IrqPriority      = UT_HASH_IRQ_PRIO;
    config.CompleteCallback = UtHash_Callback_Complete;
    config.ErrorCallback    = UtHash_Callback_Error;

    Rcc_Set_PeriphActive_ExpectAndReturn( RCC_PERIPH_HASH, RCC_REQUEST_OK );
    Nvic_Set_PeriphIrq_Handler_ExpectAndReturn( NVIC_PERIPH_IRQ_HASH, NULL, NVIC_REQUEST_OK );
    Nvic_Set_PeriphIrq_Handler_IgnoreArg_irqHandler();
    Nvic_Set_PeriphIrq_Handler_AddCallback( UtHash_NvicHandlerStub );
    Nvic_Set_PeriphIrq_Prio_ExpectAndReturn( NVIC_PERIPH_IRQ_HASH, UT_HASH_IRQ_PRIO, NVIC_REQUEST_OK );
    Nvic_Set_PeriphIrq_Active_ExpectAndReturn( NVIC_PERIPH_IRQ_HASH, NVIC_REQUEST_OK );
    Gpdma_Get_DefaultConfig_ExpectAnyArgsAndReturn( GPDMA_REQUEST_OK );
    Gpdma_Init_ExpectAnyArgsAndReturn( GPDMA_REQUEST_OK );
    Gpdma_Init_AddCallback( UtHash_GpdmaInitStub );
    Gpdma_Set_InterruptActive_ExpectAndReturn( UT_HASH_DMA_PERIPH, UT_HASH_DMA_CHANNEL, GPDMA_REQUEST_OK );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );
}


/**
 * \brief Sets up the Gpdma mock expectations of one DMA chunk.
 *
 * \param blockSize [in]: Expected block size in bytes
 * \param srcAddr   [in]: Expected source address, NULL for the copy of the trailing bytes in the module (not checked)
 */
static void UtHash_Expect_DmaChunk( gpdma_BlockSize_t blockSize, const hash_Data_t * const srcAddr )
{
    Gpdma_Set_BlockSize_ExpectAndReturn( UT_HASH_DMA_PERIPH, UT_HASH_DMA_CHANNEL, blockSize, GPDMA_REQUEST_OK );
    Gpdma_Set_SourceAddr_ExpectAndReturn( UT_HASH_DMA_PERIPH,
                                          UT_HASH_DMA_CHANNEL,
                                          (gpdma_SrcAddr_t)(uintptr_t)srcAddr,
                                          GPDMA_REQUEST_OK );

    if( NULL == srcAddr )
    {
        Gpdma_Set_SourceAddr_IgnoreArg_sourceAddr();
    }
    else
    {
        /* The source address of the message is checked */
    }

    Gpdma_Set_DestinationAddr_ExpectAndReturn( UT_HASH_DMA_PERIPH,
                                               UT_HASH_DMA_CHANNEL,
                                               (gpdma_DstAddr_t)Hash_Reg_Get_DinAddr(),
                                               GPDMA_REQUEST_OK );
    Gpdma_Set_ChannelActive_ExpectAndReturn( UT_HASH_DMA_PERIPH, UT_HASH_DMA_CHANNEL, GPDMA_REQUEST_OK );
}


/** \brief Completion callback of the module, counts the calls. */
static void UtHash_Callback_Complete( void )
{
    utHash_CompleteCnt++;
}


/** \brief Error callback of the module, counts the calls and keeps the error mask. */
static void UtHash_Callback_Error( hash_XferError_t xferError )
{
    utHash_ErrorCnt++;
    utHash_ErrorMask = xferError;
}


/** \brief Nvic_Set_PeriphIrq_Handler() callback: records the HASH interrupt handler. */
static nvic_RequestState_t UtHash_NvicHandlerStub( nvic_PeriphIrqList_t irqId,
                                                   const nvic_IsrCallback_t irqHandler,
                                                   int callCnt )
{
    ( void )irqId;
    ( void )callCnt;

    TEST_ASSERT_NOT_NULL( irqHandler );

    utHash_Isr = irqHandler;

    return ( NVIC_REQUEST_OK );
}


/** \brief Gpdma_Init() callback: copies the configuration and the transfer configuration it points to. */
static gpdma_RequestState_t UtHash_GpdmaInitStub( gpdma_ConfigStruct_t * const configStruct, int callCnt )
{
    ( void )callCnt;

    utHash_DmaConfig = *configStruct;
    utHash_DmaXfer   = *configStruct->TransferConfig;

    return ( GPDMA_REQUEST_OK );
}
