/**
 * \author Mr.Nobody
 * \file Test_Hash.c
 * \ingroup Hash
 * \brief Unit tests of the hash processor (HASH) module.
 *
 * Hash.c and Hash_Reg.c are compiled unchanged, HASH registers are emulated by
 * RegMem, RCC, NVIC and the DMA module of the line (Dma on the classic STM32H7
 * lines, Gpdma on STM32H7R / STM32H7S) are mocked by CMock.
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
 *       - DMA mode: the DMA module is mocked, no data is moved. The tests check the
 *         chunk sequence (chunk size, source address, HASH_CR.MDMAT), HASH_STR.NBLW
 *         and the end of the request: the DMA callbacks captured from Dma_Init() /
 *         Gpdma_Init() and the HASH interrupt handler captured from
 *         Nvic_Set_PeriphIrq_Handler() are called by the test. The digest of a real
 *         transfer is checked by the integration tests.
 *       - Every test case is executed in its own process (CTest), the runtime data
 *         of the module start from the reset state in every test.
 *
 * \note The test runner is generated from this file without running the preprocessor, so every test case is
 *       defined unconditionally. STM32H723 / H725, H742 / H743 / H745 / H747 and H7A3 have no HASH: the test
 *       cases ignore themselves there, only \ref Ut_Hash_NoPeripheral_EveryFunctionReturnsError and the version
 *       test run on those lines. The classic lines share the interrupt line HASH_RNG with the RNG: Hash_Init() in
 *       the ISR / DMA mode reads the state of the line first (Nvic_Get_PeriphIrq_State()).
 */

/* ============================= INCLUDES =================================== */
#include "unity.h"                          /* Unity testing framework        */
#include "RegMem.h"                         /* Register memory emulation      */
#include "Hash_Port.h"                      /* Module under test              */
#include "Hash_Reg.h"                       /* Register access of the module  */
#include "MockRcc_Port.h"                   /* RCC module mock                */
#include "MockNvic_Port.h"                  /* NVIC module mock                */
#include "MockDma_Port.h"                   /* DMA module mock (classic lines) */
#include "MockGpdma_Port.h"                 /* GPDMA module mock (STM32H7R / H7S) */
#include "Stm32.h"                          /* HASH registers definition      */
/* ============================= TYPEDEFS =================================== */

#if defined(HASH)

/* ======================= FORWARD DECLARATIONS ============================= */

static void                UtHash_Expect_InitPoll       ( void );
static void                UtHash_Expect_IrqLine        ( nvic_FunctionState_t lineState,
                                                          nvic_IsrCallback_t lineHandler );
static void                UtHash_Expect_IsrRegistration( void );
static hash_Config_t       UtHash_Get_PollConfig        ( void );
static void                UtHash_Init_Dma              ( void );
static void                UtHash_Expect_DmaChunk       ( hash_DataCnt_t chunkSize, const hash_Data_t * const srcAddr );
static void                UtHash_Expect_DmaStop        ( void );
static void                UtHash_Expect_DmaRelease     ( void );
static void                UtHash_Call_DmaComplete      ( void );
static void                UtHash_Call_DmaError         ( void );
static void                UtHash_Callback_Complete     ( void );
static void                UtHash_Callback_Error        ( hash_XferError_t xferError );

static nvic_RequestState_t  UtHash_NvicHandlerStub ( nvic_PeriphIrqList_t irqId,
                                                     const nvic_IsrCallback_t irqHandler,
                                                     int callCnt );
#if defined(STM32H7RS)
static gpdma_RequestState_t UtHash_GpdmaInitStub   ( gpdma_ConfigStruct_t * const configStruct,
                                                     int callCnt );
#else
static dma_RequestState_t   UtHash_DmaInitStub     ( dma_ConfigStruct_t * const configStruct,
                                                     int callCnt );
static void                 UtHash_OtherIsr        ( void );
#endif /* STM32H7RS */

#endif /* HASH */

/* ========================== SYMBOLIC CONSTANTS ============================= */

/** Expected version of the module */
#define UT_HASH_VERSION_MAJOR               ( 0u )
#define UT_HASH_VERSION_MINOR               ( 1u )
#define UT_HASH_VERSION_PATCH               ( 0u )

#if defined(HASH)

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

/** Digest size of MD5 */
#define UT_HASH_MD5_DIGEST_SIZE              ( 16u )

/** Digest size of SHA2-256 */
#define UT_HASH_SHA256_DIGEST_SIZE           ( 32u )

/** Known digest word preset into HASH_HR0 by the tests (arbitrary pattern, big-endian readback check) */
#define UT_HASH_DIGEST_WORD0                 ( 0x01020304u )

/** Byte offset of HASH_HR0 from the HASH base address (RM0433 / RM0477 HASH digest registers) */
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

#if defined(STM32H7RS)
/** Gpdma channel of the DMA mode tests */
#define UT_HASH_DMA_PERIPH                     ( GPDMA_PERIPH_1 )
#define UT_HASH_DMA_CHANNEL                    ( GPDMA_CHANNEL_5 )

/** Gpdma errors the DMA mode shall report (the suspension is left out) */
#define UT_HASH_DMA_ERROR_MASK                 ( GPDMA_ERROR_TRANSFER      | \
                                                 GPDMA_ERROR_CONFIG_UPDATE | \
                                                 GPDMA_ERROR_CONFIG_ERROR  | \
                                                 GPDMA_ERROR_TRIG_OVERRUN )

/** Default DMA controller, channel and priority of Hash_Get_DefaultConfig() */
#define UT_HASH_DMA_DEFAULT_PERIPH             ( GPDMA_PERIPH_1 )
#define UT_HASH_DMA_DEFAULT_CHANNEL            ( GPDMA_CHANNEL_0 )
#define UT_HASH_DMA_DEFAULT_PRIO               ( GPDMA_PRIORITY_LOW )

/** Largest DMA chunk: the biggest multiple of four words within the 16-bit Gpdma block size */
#define UT_HASH_DMA_CHUNK_MAX                  ( 65520u )

/** Interrupt line of the HASH (own line on STM32H7R / H7S) */
#define UT_HASH_NVIC_IRQ                       ( NVIC_PERIPH_IRQ_HASH )
#else
/** Dma stream of the DMA mode tests */
#define UT_HASH_DMA_PERIPH                     ( DMA_PERIPH_2 )
#define UT_HASH_DMA_CHANNEL                    ( DMA_STREAM_5 )

/** Default DMA controller, stream and priority of Hash_Get_DefaultConfig() */
#define UT_HASH_DMA_DEFAULT_PERIPH             ( DMA_PERIPH_1 )
#define UT_HASH_DMA_DEFAULT_CHANNEL            ( DMA_STREAM_0 )
#define UT_HASH_DMA_DEFAULT_PRIO               ( DMA_PRIORITY_LOW )

/** Largest DMA chunk: the biggest multiple of four words within 65535 data items of DMA_SxNDTR */
#define UT_HASH_DMA_CHUNK_MAX                  ( 262128u )

/** Count of bytes of one 32-bit data item of the Dma stream */
#define UT_HASH_DMA_ITEM_SIZE                  ( 4u )

/** Interrupt line of the HASH, shared with the RNG on the classic lines */
#define UT_HASH_NVIC_IRQ                       ( NVIC_PERIPH_IRQ_HASH_RNG )
#endif /* STM32H7RS */

/** Block size of the one word chunk of the 3 trailing bytes of "abc" */
#define UT_HASH_DMA_ABC_BLOCK                  ( 4u )

/** Long DMA message: one full chunk (\ref UT_HASH_DMA_CHUNK_MAX bytes), 32 more bytes (multiple of four words) and
 *  5 trailing bytes */
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

#if defined(STM32H7RS)
/** Gpdma configuration captured from Gpdma_Init() (the transfer configuration it points to is copied) */
static gpdma_ConfigStruct_t   utHash_DmaConfig;
static gpdma_TransferConfig_t utHash_DmaXfer;
#else
/** Dma configuration captured from Dma_Init() */
static dma_ConfigStruct_t     utHash_DmaConfig;

/** State and handler of the interrupt line HASH_RNG returned by the Nvic mock */
static nvic_FunctionState_t   utHash_LineState;
static nvic_IsrCallback_t     utHash_LineHandler;
#endif /* STM32H7RS */

/** Number of the completion / error callbacks and the last reported error mask */
static uint32_t         utHash_CompleteCnt;
static uint32_t         utHash_ErrorCnt;
static hash_XferError_t utHash_ErrorMask;

#endif /* HASH */

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
 * - HASH_REQUEST_OK, POLL transfer mode, DMA1 stream 0 (classic lines) / GPDMA1 channel 0 (STM32H7R / H7S) at
 *   low priority, IRQ prio 0, no callbacks.
 * - NULL pointer: HASH_REQUEST_ERROR.
 */
void Ut_Hash_Get_DefaultConfig_ReturnsDefaults( void )
{
#if defined(HASH)
    hash_Config_t config;

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_DefaultConfig( &config ) );

    TEST_ASSERT_EQUAL( HASH_XFER_MODE_POLL, config.XferMode );
    TEST_ASSERT_EQUAL( UT_HASH_DMA_DEFAULT_PERIPH, config.DmaPeriphId );
    TEST_ASSERT_EQUAL( UT_HASH_DMA_DEFAULT_CHANNEL, config.DmaChannelId );
    TEST_ASSERT_EQUAL( UT_HASH_DMA_DEFAULT_PRIO, config.DmaChannelPrio );
    TEST_ASSERT_EQUAL_UINT32( UT_HASH_REG_ZERO, config.IrqPriority );
    TEST_ASSERT_NULL( config.CompleteCallback );
    TEST_ASSERT_NULL( config.ErrorCallback );

    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Get_DefaultConfig( NULL ) );
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
}

/* ============================ NO PERIPHERAL ================================= */

/**
 * \brief   Every function returns HASH_REQUEST_ERROR on a device line without the HASH peripheral.
 *
 * \details STM32H723 / H725, H742 / H743 / H745 / H747 and H7A3 have no HASH. The case is ignored on the other
 *          lines.
 *
 * \par Expected results
 * - HASH_REQUEST_ERROR from every function that returns a request state, no RCC / NVIC / DMA call (strict mocks),
 *   Hash_Task() returns.
 */
void Ut_Hash_NoPeripheral_EveryFunctionReturnsError( void )
{
#if !defined(HASH)
    hash_Config_t        config      = { 0 };
    hash_Request_t       request     = { 0 };
    hash_StartConfig_t   startConfig = { 0 };
    hash_Context_t       context     = { { 0 } };
    hash_FunctionState_t supported   = HASH_FUNCTION_INACTIVE;
    hash_DataCnt_t       digestSize  = 0u;
    hash_State_t         hashState   = HASH_STATE_IDLE;
    hash_XferError_t     xferError   = HASH_XFER_ERROR_NONE;
    hash_IrqPrio_t       irqPrio     = 0u;
    hash_Data_t          data[ 4 ]   = { 0u };

    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Get_DefaultConfig( &config ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Init( &config ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Deinit() );
    Hash_Task();
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Get_Capability( HASH_ALGO_SHA1, &supported ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Get_DigestSize( HASH_ALGO_SHA1, &digestSize ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Get_State( &hashState ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Get_XferError( &xferError ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Set_Calculate( &request ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Set_Start( &startConfig ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Set_Update( data, sizeof( data ) ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Set_Finish( data, sizeof( data ) ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Set_Abort() );
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Get_Context( &context ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Set_Context( &context ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Set_IrqPriority( irqPrio ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Get_IrqPriority( &irqPrio ) );
#else
    TEST_IGNORE_MESSAGE( "Device line with the HASH peripheral, see the other test cases" );
#endif /* !HASH */
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
#if defined(HASH)
    hash_State_t   hashState;
    hash_Config_t config = UtHash_Get_PollConfig();

    UtHash_Expect_InitPoll();

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_State( &hashState ) );
    TEST_ASSERT_EQUAL( HASH_STATE_IDLE, hashState );
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
}


/**
 * \brief   Hash_Init() in ISR mode registers the handler and activates the interrupt enable bits.
 *
 * \par Expected results
 * - Classic lines: the state of the interrupt line HASH_RNG is read first (not activated).
 * - HASH_REQUEST_OK, HASH_IMR has DCIE and DINIE set.
 */
void Ut_Hash_Init_Isr_ActivatesInterrupt( void )
{
#if defined(HASH)
    hash_Config_t config = UtHash_Get_PollConfig();

    config.XferMode   = HASH_XFER_MODE_ISR;
    config.IrqPriority = UT_HASH_IRQ_PRIO;

    Rcc_Set_PeriphActive_ExpectAndReturn( RCC_PERIPH_HASH, RCC_REQUEST_OK );
    UtHash_Expect_IrqLine( NVIC_FUNCTION_INACTIVE, NULL );
    UtHash_Expect_IsrRegistration();

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );
    TEST_ASSERT_EQUAL_HEX32( ( HASH_IMR_DCIE | HASH_IMR_DINIE ), HASH->IMR );
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
}


/**
 * \brief   Hash_Init() in ISR mode rejects the interrupt line HASH_RNG activated with another handler (classic
 *          lines: the Rng module in its interrupt mode owns the line shared with the RNG).
 *
 * \par Expected results
 * - Classic lines: HASH_REQUEST_ERROR, the line is neither registered nor configured (strict mocks), HASH_IMR
 *   stays clear.
 * - STM32H7R / H7S: ignored (own interrupt line of the HASH).
 */
void Ut_Hash_Init_Isr_LineOfOtherHandler_ReturnsError( void )
{
#if defined(HASH)
#if !defined(STM32H7RS)
    hash_Config_t config = UtHash_Get_PollConfig();

    config.XferMode    = HASH_XFER_MODE_ISR;
    config.IrqPriority = UT_HASH_IRQ_PRIO;

    Rcc_Set_PeriphActive_ExpectAndReturn( RCC_PERIPH_HASH, RCC_REQUEST_OK );
    UtHash_Expect_IrqLine( NVIC_FUNCTION_ACTIVE, UtHash_OtherIsr );

    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Init( &config ) );
    TEST_ASSERT_EQUAL_HEX32( UT_HASH_REG_ZERO, HASH->IMR );
#else
    TEST_IGNORE_MESSAGE( "STM32H7R / H7S: own interrupt line of the HASH" );
#endif /* !STM32H7RS */
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
}


/**
 * \brief   A repeated Hash_Init() in ISR mode accepts the interrupt line HASH_RNG activated with the HASH handler.
 *
 * \par Expected results
 * - Classic lines: both calls return HASH_REQUEST_OK, the second one reads the state of the line and its handler
 *   (the one registered by the first call) and registers the line again.
 * - STM32H7R / H7S: ignored (own interrupt line of the HASH).
 */
void Ut_Hash_Init_Isr_LineOfHashHandler_ReturnsOk( void )
{
#if defined(HASH)
#if !defined(STM32H7RS)
    hash_Config_t config = UtHash_Get_PollConfig();

    config.XferMode    = HASH_XFER_MODE_ISR;
    config.IrqPriority = UT_HASH_IRQ_PRIO;

    Rcc_Set_PeriphActive_ExpectAndReturn( RCC_PERIPH_HASH, RCC_REQUEST_OK );
    UtHash_Expect_IrqLine( NVIC_FUNCTION_INACTIVE, NULL );
    UtHash_Expect_IsrRegistration();
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );

    Rcc_Set_PeriphActive_ExpectAndReturn( RCC_PERIPH_HASH, RCC_REQUEST_OK );
    UtHash_Expect_IrqLine( NVIC_FUNCTION_ACTIVE, utHash_Isr );
    UtHash_Expect_IsrRegistration();
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );
#else
    TEST_IGNORE_MESSAGE( "STM32H7R / H7S: own interrupt line of the HASH" );
#endif /* !STM32H7RS */
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
}


/**
 * \brief   Hash_Init() rejects a NULL configuration and an invalid transfer mode.
 *
 * \par Expected results
 * - Both calls return HASH_REQUEST_ERROR, RCC / NVIC are never called.
 */
void Ut_Hash_Init_InvalidArgs_ReturnsErrorWithoutAccess( void )
{
#if defined(HASH)
    hash_Config_t config = UtHash_Get_PollConfig();

    config.XferMode = HASH_XFER_MODE_CNT;

    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Init( NULL ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Init( &config ) );
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
}


/**
 * \brief   Hash_Deinit() after the POLL mode deactivates the module without touching the interrupt line (shared with
 *          the RNG on the classic lines).
 *
 * \par Expected results
 * - HASH_REQUEST_OK without any Nvic call (strict mocks), Hash_Get_State() returns HASH_REQUEST_ERROR afterwards
 *   (not initialized).
 */
void Ut_Hash_Deinit_DeactivatesModule( void )
{
#if defined(HASH)
    hash_State_t   hashState;
    hash_Config_t config = UtHash_Get_PollConfig();

    UtHash_Expect_InitPoll();
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Deinit() );

    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Get_State( &hashState ) );
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
}

/* ============================== CAPABILITY ================================== */

/**
 * \brief   Hash_Get_Capability() reports SHA-1 active on every line, MD5 active on the classic lines only (the
 *          STM32H7R / H7S HASH has no MD5 encoding of HASH_CR.ALGO).
 *
 * \par Expected results
 * - HASH_REQUEST_OK for both, SHA-1 active; MD5 active with the 16 byte digest on the classic lines, inactive on
 *   STM32H7R / H7S.
 */
void Ut_Hash_Get_Capability_Sha1AndMd5_MatchLine( void )
{
#if defined(HASH)
    hash_FunctionState_t supported;
    hash_DataCnt_t        digestSize = 0u;
    hash_Config_t         config     = UtHash_Get_PollConfig();

    UtHash_Expect_InitPoll();
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_Capability( HASH_ALGO_SHA1, &supported ) );
    TEST_ASSERT_EQUAL( HASH_FUNCTION_ACTIVE, supported );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_Capability( HASH_ALGO_MD5, &supported ) );
#if defined(STM32H7RS)
    TEST_ASSERT_EQUAL( HASH_FUNCTION_INACTIVE, supported );
#else
    TEST_ASSERT_EQUAL( HASH_FUNCTION_ACTIVE, supported );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_DigestSize( HASH_ALGO_MD5, &digestSize ) );
    TEST_ASSERT_EQUAL_UINT32( UT_HASH_MD5_DIGEST_SIZE, digestSize );
#endif /* STM32H7RS */
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
}


/**
 * \brief   Hash_Get_Capability() reports SHA2-384 per the device line (STM32H7R / H7S only, the classic HASH has a
 *          2 bit HASH_CR.ALGO field without the 1024-bit block algorithms).
 *
 * \par Expected results
 * - HASH_FUNCTION_ACTIVE on STM32H7R / H7S, HASH_FUNCTION_INACTIVE on the classic lines.
 */
void Ut_Hash_Get_Capability_Sha2_384_MatchesLine( void )
{
#if defined(HASH)
    hash_FunctionState_t supported;
    hash_FunctionState_t expected = HASH_FUNCTION_INACTIVE;
    hash_Config_t         config   = UtHash_Get_PollConfig();

#if defined(STM32H7RS)
    expected = HASH_FUNCTION_ACTIVE;
#else
    expected = HASH_FUNCTION_INACTIVE;
#endif /* STM32H7RS */

    UtHash_Expect_InitPoll();
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_Capability( HASH_ALGO_SHA2_384, &supported ) );
    TEST_ASSERT_EQUAL( expected, supported );
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
}


/**
 * \brief   Hash_Get_Capability() reports SHA3-256 inactive: no STM32H7 line implements SHA-3 (RM0433 / RM0399 /
 *          RM0455 / RM0468 HASH chapters, RM0477 block diagram).
 *
 * \par Expected results
 * - HASH_REQUEST_OK, HASH_FUNCTION_INACTIVE.
 */
void Ut_Hash_Get_Capability_Sha3_256_Inactive( void )
{
#if defined(HASH)
    hash_FunctionState_t supported = HASH_FUNCTION_ACTIVE;
    hash_Config_t         config    = UtHash_Get_PollConfig();

    UtHash_Expect_InitPoll();
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_Capability( HASH_ALGO_SHA3_256, &supported ) );
    TEST_ASSERT_EQUAL( HASH_FUNCTION_INACTIVE, supported );
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
}


/**
 * \brief   Hash_Get_Capability() rejects a NULL output pointer and an out of range algorithm.
 *
 * \par Expected results
 * - Both calls return HASH_REQUEST_ERROR.
 */
void Ut_Hash_Get_Capability_InvalidArgs_ReturnsError( void )
{
#if defined(HASH)
    hash_FunctionState_t supported;
    hash_Config_t         config = UtHash_Get_PollConfig();

    UtHash_Expect_InitPoll();
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );

    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Get_Capability( HASH_ALGO_SHA1, NULL ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Get_Capability( HASH_ALGO_CNT, &supported ) );
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
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
#if defined(HASH)
    hash_FunctionState_t supported;
    hash_DataCnt_t        digestSize;

    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Get_Capability( HASH_ALGO_SHA1, &supported ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Get_DigestSize( HASH_ALGO_SHA1, &digestSize ) );
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
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
#if defined(HASH)
    hash_DataCnt_t digestSize;
    hash_Config_t  config = UtHash_Get_PollConfig();

    UtHash_Expect_InitPoll();
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_DigestSize( HASH_ALGO_SHA2_256, &digestSize ) );
    TEST_ASSERT_EQUAL_UINT32( UT_HASH_SHA256_DIGEST_SIZE, digestSize );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_DigestSize( HASH_ALGO_SHAKE128, &digestSize ) );
    TEST_ASSERT_EQUAL_UINT32( UT_HASH_REG_ZERO, digestSize );
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
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
#if defined(HASH)
    hash_State_t   hashState = HASH_STATE_ERROR;
    hash_Config_t config     = UtHash_Get_PollConfig();

    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Get_State( &hashState ) );

    UtHash_Expect_InitPoll();
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_State( &hashState ) );
    TEST_ASSERT_EQUAL( HASH_STATE_IDLE, hashState );
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
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
#if defined(HASH)
    hash_XferError_t xferError;

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_XferError( &xferError ) );
    TEST_ASSERT_EQUAL( HASH_XFER_ERROR_NONE, xferError );
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Get_XferError( NULL ) );
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
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
#if defined(HASH)
    hash_Data_t    digest[ UT_HASH_SHA1_DIGEST_SIZE ];
    hash_Config_t  config  = UtHash_Get_PollConfig();
    hash_Request_t request = { 0 };

    UtHash_Expect_InitPoll();
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );

    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Set_Calculate( NULL ) );

    request.Algorithm  = HASH_ALGO_SHA3_256;   /* No SHA-3 on STM32H7 */
    request.Mode       = HASH_MODE_HASH;
    request.Input       = utHash_Abc;
    request.InputSize   = sizeof( utHash_Abc );
    request.Digest      = digest;
    request.DigestSize  = sizeof( digest );

    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Set_Calculate( &request ) );
    TEST_ASSERT_EQUAL_HEX32( UT_HASH_REG_ZERO, HASH->CR );
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
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
#if defined(HASH)
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
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
}


/**
 * \brief   Hash_Set_Calculate() computes MD5 of "abc" in POLL mode on the classic lines (HASH_CR.ALGO[1:0] = 01,
 *          ALGO[0] at bit 7), the STM32H7R / H7S HASH has no MD5.
 *
 * \par Expected results
 * - Classic lines: HASH_REQUEST_OK, HASH_CR.ALGO = ALGO[0], the 16 byte digest is read back most significant byte
 *   first.
 * - STM32H7R / H7S: HASH_REQUEST_ERROR, no register is written (HASH_CR stays 0).
 */
void Ut_Hash_Set_Calculate_Md5Poll_MatchesLine( void )
{
#if defined(HASH)
    hash_Data_t    digest[ UT_HASH_MD5_DIGEST_SIZE ];
    hash_Config_t  config  = UtHash_Get_PollConfig();
    hash_Request_t request = { 0 };

    UtHash_Expect_InitPoll();
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );

    Hash_Set_RegVal( HASH_REG_SR, ( HASH_SR_DINIS | HASH_SR_DCIS ), ( HASH_SR_DINIS | HASH_SR_DCIS ) );
    *( (volatile uint32_t *)( (uint8_t *)HASH + UT_HASH_HR_BASE_OFFSET ) ) = UT_HASH_DIGEST_WORD0;

    request.Algorithm  = HASH_ALGO_MD5;
    request.Mode       = HASH_MODE_HASH;
    request.Input      = utHash_Abc;
    request.InputSize  = sizeof( utHash_Abc );
    request.Digest     = digest;
    request.DigestSize = sizeof( digest );

#if defined(STM32H7RS)
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Set_Calculate( &request ) );
    TEST_ASSERT_EQUAL_HEX32( UT_HASH_REG_ZERO, HASH->CR );
#else
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Calculate( &request ) );
    TEST_ASSERT_EQUAL_HEX32( HASH_CR_ALGO_0, ( HASH->CR & HASH_CR_ALGO ) );
    TEST_ASSERT_EQUAL_UINT8( UT_HASH_DIGEST_BYTE_0, digest[ 0 ] );
    TEST_ASSERT_EQUAL_UINT8( UT_HASH_DIGEST_BYTE_3, digest[ UT_HASH_ABC_IDX_3 ] );
#endif /* STM32H7RS */
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
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
#if defined(HASH)
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
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
}


/**
 * \brief   Hash_Set_Calculate() rejects HASH_MODE_HMAC in DMA transfer mode.
 *
 * \par Expected results
 * - HASH_REQUEST_ERROR, the DMA module is never called.
 */
void Ut_Hash_Set_Calculate_HmacDma_ReturnsErrorWithoutDma( void )
{
#if defined(HASH)
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
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
}

/* ================================= DMA MODE ======================================= */

/**
 * \brief   Hash_Init() in DMA mode initializes the DMA channel and activates its interrupts.
 *
 * \par Expected results
 * - Classic lines: HASH_REQUEST_OK, Dma_Init() gets the stream of the configuration, the HASH_IN request, 32-bit data
 *   items from the incremented memory address to the static HASH_DIN address (normal mode), the priority of the
 *   configuration, the transfer complete and the transfer error callbacks without a half transfer callback; the
 *   transfer error and the transfer complete interrupts and the interrupt line of the stream are activated.
 * - STM32H7R / H7S: HASH_REQUEST_OK, Gpdma_Init() gets the HASH input request with single requests, 32-bit words
 *   from the memory to the static HASH_DIN address, both callbacks and the error mask without the suspension;
 *   Gpdma_Set_InterruptActive() of the channel follows.
 */
void Ut_Hash_Init_Dma_InitializesChannel( void )
{
#if defined(HASH)
    UtHash_Init_Dma();

#if defined(STM32H7RS)
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
#else
    TEST_ASSERT_EQUAL( UT_HASH_DMA_PERIPH, utHash_DmaConfig.DmaPeriphId );
    TEST_ASSERT_EQUAL( UT_HASH_DMA_CHANNEL, utHash_DmaConfig.DmaChannel );
    TEST_ASSERT_EQUAL( DMA_REQ_HASH_IN, utHash_DmaConfig.PeripheralReqId );
    TEST_ASSERT_EQUAL( DMA_DIR_MEMORY_TO_PERIPH, utHash_DmaConfig.Direction );
    TEST_ASSERT_EQUAL( DMA_TRANSFER_MODE_NORMAL, utHash_DmaConfig.TransferMode );
    TEST_ASSERT_EQUAL( DMA_TRANSFER_SIZE_32BIT, utHash_DmaConfig.PeriphTransferSize );
    TEST_ASSERT_EQUAL( DMA_TRANSFER_SIZE_32BIT, utHash_DmaConfig.MemoryTransferSize );
    TEST_ASSERT_EQUAL( DMA_PERIPH_ADDR_STATIC, utHash_DmaConfig.PeriphAddrIncrement );
    TEST_ASSERT_EQUAL( DMA_MEMORY_ADDR_INCREMENT, utHash_DmaConfig.MemoryAddrIncrement );
    TEST_ASSERT_EQUAL( UT_HASH_DMA_DEFAULT_PRIO, utHash_DmaConfig.Priority );
    TEST_ASSERT_EQUAL_HEX32( Hash_Reg_Get_DinAddr(), utHash_DmaConfig.PeriphAddress );
    TEST_ASSERT_NOT_NULL( utHash_DmaConfig.TransferCompleteCallback );
    TEST_ASSERT_NOT_NULL( utHash_DmaConfig.TransferErrorCallback );
    TEST_ASSERT_NULL( utHash_DmaConfig.HalfTransferCallback );
#endif /* STM32H7RS */
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
}


/**
 * \brief   Hash_Init() in DMA mode rejects HPDMA1 on STM32H7R / H7S (only GPDMA1 has the request HASH_IN).
 *
 * \par Expected results
 * - STM32H7R / H7S: HASH_REQUEST_ERROR, Gpdma_Init() is not called (strict mocks), the module stays not initialized
 *   (Hash_Get_State() returns HASH_REQUEST_ERROR).
 * - Classic lines: ignored (DMA1 and DMA2 both serve HASH_IN through DMAMUX1).
 */
void Ut_Hash_Init_DmaHpdma1_ReturnsError( void )
{
#if defined(HASH)
#if defined(STM32H7RS)
    hash_State_t  hashState = HASH_STATE_IDLE;
    hash_Config_t config    = UtHash_Get_PollConfig();

    config.XferMode     = HASH_XFER_MODE_DMA;
    config.DmaPeriphId  = GPDMA_PERIPH_2;
    config.DmaChannelId = UT_HASH_DMA_CHANNEL;
    config.IrqPriority  = UT_HASH_IRQ_PRIO;

    Rcc_Set_PeriphActive_ExpectAndReturn( RCC_PERIPH_HASH, RCC_REQUEST_OK );
    UtHash_Expect_IsrRegistration();
    Gpdma_Get_DefaultConfig_ExpectAnyArgsAndReturn( GPDMA_REQUEST_OK );

    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Init( &config ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Get_State( &hashState ) );
#else
    TEST_IGNORE_MESSAGE( "Classic lines: DMA1 and DMA2 both serve HASH_IN through DMAMUX1" );
#endif /* STM32H7RS */
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
}


/**
 * \brief   Hash_Set_Calculate() in DMA mode rejects an input that is not word aligned.
 *
 * \par Expected results
 * - HASH_REQUEST_ERROR, no DMA call after the initialization (the mock fails on an unexpected call), HASH_CR.DMAE
 *   stays clear.
 */
void Ut_Hash_Set_Calculate_DmaUnalignedInput_ReturnsErrorWithoutDma( void )
{
#if defined(HASH)
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
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
}


/**
 * \brief   A DMA request of "abc" sends the 3 bytes as one word chunk and ends by the HASH digest interrupt; a second
 *          request reuses the channel without a new DMA initialization.
 *
 * \par Expected results
 * - Start: HASH_REQUEST_OK, NBLW = 24, DMAE set, MDMAT clear (single chunk), a one word chunk is started, the state
 *   is BUSY and Hash_Set_Update() is rejected (no incremental calculation is open).
 * - DMA transfer complete: DCIE set, no callback yet.
 * - HASH interrupt with DCIS: digest[0..3] equal HASH_HR0 most significant byte first, DCIS, DCIE and DMAE cleared,
 *   the state is IDLE, one completion callback.
 * - The second request starts its chunk without a DMA initialization (the mock fails on an unexpected call).
 */
void Ut_Hash_Set_Calculate_DmaShortMessage_EndsByDigestInterrupt( void )
{
#if defined(HASH)
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

    UtHash_Call_DmaComplete();

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
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
}


/**
 * \brief   A DMA request longer than one DMA chunk is split: full chunks with MDMAT set, the trailing bytes as the
 *          last chunk with MDMAT clear.
 *
 * \details \ref UT_HASH_DMA_CHUNK_MAX (the largest multiple of four words within one DMA block: 65520 bytes of the
 *          16-bit Gpdma block size, 262128 bytes of 65535 words of a Dma stream) + 32 + 5 trailing bytes.
 *
 * \par Expected results
 * - NBLW = 8 (1 valid byte in the last word).
 * - Chunk 1: \ref UT_HASH_DMA_CHUNK_MAX bytes from the message start, MDMAT set.
 * - Chunk 2: 32 bytes from the message start + \ref UT_HASH_DMA_CHUNK_MAX, MDMAT set.
 * - Chunk 3: the 5 trailing bytes as 8 bytes from the copy in the module, MDMAT clear.
 * - DCIE is set only after the transfer complete of the last chunk.
 */
void Ut_Hash_Set_Calculate_DmaLongMessage_SplitsChunks( void )
{
#if defined(HASH)
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
    UtHash_Call_DmaComplete();
    TEST_ASSERT_EQUAL_HEX32( HASH_CR_MDMAT, ( HASH->CR & HASH_CR_MDMAT ) );
    TEST_ASSERT_EQUAL_HEX32( UT_HASH_REG_ZERO, ( HASH->IMR & HASH_IMR_DCIE ) );

    UtHash_Expect_DmaChunk( UT_HASH_DMA_TAIL_BLOCK, NULL );
    UtHash_Call_DmaComplete();
    TEST_ASSERT_EQUAL_HEX32( UT_HASH_REG_ZERO, ( HASH->CR & HASH_CR_MDMAT ) );
    TEST_ASSERT_EQUAL_HEX32( UT_HASH_REG_ZERO, ( HASH->IMR & HASH_IMR_DCIE ) );

    UtHash_Call_DmaComplete();
    TEST_ASSERT_EQUAL_HEX32( HASH_IMR_DCIE, ( HASH->IMR & HASH_IMR_DCIE ) );
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
}


/**
 * \brief   A DMA request of an empty message is padded by software and ends by the digest interrupt as well.
 *
 * \par Expected results
 * - HASH_REQUEST_OK without any DMA call, DCAL written, DMAE clear, DCIE set right away.
 * - HASH interrupt with DCIS: the state is IDLE, one completion callback.
 */
void Ut_Hash_Set_Calculate_DmaEmptyMessage_PadsBySoftware( void )
{
#if defined(HASH)
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
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
}


/**
 * \brief   A DMA transfer error ends the running DMA request with a DMA transfer error.
 *
 * \par Expected results
 * - The state is ERROR, one error callback with HASH_XFER_ERROR_DMA, DMAE and DCIE clear, no completion callback.
 * - A transfer complete reported after the error does not continue the request (no DMA call, DCIE stays clear).
 */
void Ut_Hash_DmaError_EndsRequestWithDmaError( void )
{
#if defined(HASH)
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

    UtHash_Call_DmaError();

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_State( &hashState ) );
    TEST_ASSERT_EQUAL( HASH_STATE_ERROR, hashState );
    TEST_ASSERT_EQUAL_UINT32( 1u, utHash_ErrorCnt );
    TEST_ASSERT_EQUAL( HASH_XFER_ERROR_DMA, utHash_ErrorMask );
    TEST_ASSERT_EQUAL_HEX32( UT_HASH_REG_ZERO, ( HASH->CR & HASH_CR_DMAE ) );

    UtHash_Call_DmaComplete();

    TEST_ASSERT_EQUAL_HEX32( UT_HASH_REG_ZERO, ( HASH->IMR & HASH_IMR_DCIE ) );
    TEST_ASSERT_EQUAL_UINT32( 0u, utHash_CompleteCnt );
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
}


/**
 * \brief   Hash_Set_Abort() stops a running DMA request.
 *
 * \par Expected results
 * - HASH_REQUEST_OK, the DMA channel is stopped (Dma_Set_TransferInactive() / Gpdma_Set_ChannelInactive()), DMAE
 *   and DCIE clear, INIT set, the state is IDLE.
 * - A transfer complete reported after the abort does not continue the request, no callback.
 */
void Ut_Hash_Set_Abort_DmaRequest_StopsChannel( void )
{
#if defined(HASH)
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

    UtHash_Expect_DmaStop();
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Abort() );

    TEST_ASSERT_EQUAL_HEX32( UT_HASH_REG_ZERO, ( HASH->CR & ( HASH_CR_DMAE | HASH_CR_MDMAT ) ) );
    TEST_ASSERT_EQUAL_HEX32( HASH_CR_INIT, ( HASH->CR & HASH_CR_INIT ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_State( &hashState ) );
    TEST_ASSERT_EQUAL( HASH_STATE_IDLE, hashState );

    UtHash_Call_DmaComplete();

    TEST_ASSERT_EQUAL_HEX32( UT_HASH_REG_ZERO, ( HASH->IMR & HASH_IMR_DCIE ) );
    TEST_ASSERT_EQUAL_UINT32( 0u, utHash_CompleteCnt );
    TEST_ASSERT_EQUAL_UINT32( 0u, utHash_ErrorCnt );
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
}


/**
 * \brief   Hash_Deinit() in DMA mode releases the DMA channel and the interrupt line of the HASH.
 *
 * \par Expected results
 * - HASH_REQUEST_OK, the DMA channel is released first (Dma_Set_TransferInactive() / Gpdma_Deinit() and the
 *   interrupt line of the channel off), then the interrupt line of the HASH is deactivated.
 */
void Ut_Hash_Deinit_Dma_ReleasesChannel( void )
{
#if defined(HASH)
    UtHash_Init_Dma();

    UtHash_Expect_DmaRelease();
    Nvic_Set_PeriphIrq_Inactive_ExpectAndReturn( UT_HASH_NVIC_IRQ, NVIC_REQUEST_OK );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Deinit() );
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
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
#if defined(HASH)
    hash_StartConfig_t  startConfig = { 0 };

    UtHash_Init_Dma();

    startConfig.Algorithm = HASH_ALGO_SHA1;
    startConfig.Mode       = HASH_MODE_HASH;

    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Set_Start( &startConfig ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Set_Update( utHash_Abc, sizeof( utHash_Abc ) ) );
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
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
#if defined(HASH)
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
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
}


/**
 * \brief   Hash_Set_Update() rejects data when no calculation is open.
 *
 * \par Expected results
 * - HASH_REQUEST_ERROR.
 */
void Ut_Hash_Set_Update_NoCalcOpen_ReturnsError( void )
{
#if defined(HASH)
    TEST_ASSERT_EQUAL( HASH_REQUEST_ERROR, Hash_Set_Update( utHash_Abc, sizeof( utHash_Abc ) ) );
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
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
#if defined(HASH)
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
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
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
#if defined(HASH)
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
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
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
#if defined(HASH)
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
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
}


/**
 * \brief   Hash_Set_Context() rejects a NULL context and a calculation already open.
 *
 * \par Expected results
 * - Both calls return HASH_REQUEST_ERROR.
 */
void Ut_Hash_Set_Context_InvalidArgs_ReturnsError( void )
{
#if defined(HASH)
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
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
}

/* ================================= INTERRUPTS ======================================= */

/**
 * \brief   Hash_Set_IrqPriority() / Hash_Get_IrqPriority() forward to Nvic.
 *
 * \par Expected results
 * - Both calls return HASH_REQUEST_OK and use the interrupt line of the HASH (HASH_RNG on the classic lines).
 */
void Ut_Hash_IrqPriority_SetAndGet_UsesNvic( void )
{
#if defined(HASH)
    hash_IrqPrio_t irqPrio = UT_HASH_REG_ZERO;

    Nvic_Set_PeriphIrq_Prio_ExpectAndReturn( UT_HASH_NVIC_IRQ, UT_HASH_IRQ_PRIO, NVIC_REQUEST_OK );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_IrqPriority( UT_HASH_IRQ_PRIO ) );

    Nvic_Get_PeriphIrq_Prio_ExpectAndReturn( UT_HASH_NVIC_IRQ, NULL, NVIC_REQUEST_OK );
    Nvic_Get_PeriphIrq_Prio_IgnoreArg_irqPrio();
    Nvic_Get_PeriphIrq_Prio_ReturnThruPtr_irqPrio( &irqPrio );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_IrqPriority( &irqPrio ) );
#else
    TEST_IGNORE_MESSAGE( "Device line without the HASH peripheral" );
#endif /* HASH */
}

/* =========================== LOCAL FUNCTIONS =============================== */

#if defined(HASH)

/**
 * \brief Sets up the Rcc / Nvic mock expectations of Hash_Init() in POLL mode.
 */
static void UtHash_Expect_InitPoll( void )
{
    Rcc_Set_PeriphActive_ExpectAndReturn( RCC_PERIPH_HASH, RCC_REQUEST_OK );
}


/**
 * \brief Sets up the Nvic mock expectations of the check of the interrupt line HASH_RNG shared with the RNG (classic
 *        lines, Hash_Init() in the ISR / DMA mode): the state of the line and, for an activated line, its handler.
 *        Nothing on STM32H7R / H7S (own interrupt line of the HASH).
 *
 * \param lineState   [in]: Activation state of the line returned by the mock
 * \param lineHandler [in]: Handler of the activated line returned by the mock
 */
static void UtHash_Expect_IrqLine( nvic_FunctionState_t lineState, nvic_IsrCallback_t lineHandler )
{
#if defined(STM32H7RS)
    (void)lineState;
    (void)lineHandler;
#else
    utHash_LineState   = lineState;
    utHash_LineHandler = lineHandler;

    Nvic_Get_PeriphIrq_State_ExpectAndReturn( UT_HASH_NVIC_IRQ, NULL, NVIC_REQUEST_OK );
    Nvic_Get_PeriphIrq_State_IgnoreArg_irqState();
    Nvic_Get_PeriphIrq_State_ReturnThruPtr_irqState( &utHash_LineState );

    if( NVIC_FUNCTION_ACTIVE == lineState )
    {
        Nvic_Get_PeriphIrq_Handler_ExpectAndReturn( UT_HASH_NVIC_IRQ, NULL, NVIC_REQUEST_OK );
        Nvic_Get_PeriphIrq_Handler_IgnoreArg_irqHandler();
        Nvic_Get_PeriphIrq_Handler_ReturnThruPtr_irqHandler( &utHash_LineHandler );
    }
    else
    {
        /* The handler of a line that is not activated is not read */
    }
#endif /* STM32H7RS */
}


/**
 * \brief Sets up the Nvic mock expectations of the registration of the HASH interrupt handler (captured by
 *        \ref UtHash_NvicHandlerStub) with \ref UT_HASH_IRQ_PRIO and of the activation of the line.
 */
static void UtHash_Expect_IsrRegistration( void )
{
    Nvic_Set_PeriphIrq_Handler_ExpectAndReturn( UT_HASH_NVIC_IRQ, NULL, NVIC_REQUEST_OK );
    Nvic_Set_PeriphIrq_Handler_IgnoreArg_irqHandler();
    Nvic_Set_PeriphIrq_Handler_AddCallback( UtHash_NvicHandlerStub );
    Nvic_Set_PeriphIrq_Prio_ExpectAndReturn( UT_HASH_NVIC_IRQ, UT_HASH_IRQ_PRIO, NVIC_REQUEST_OK );
    Nvic_Set_PeriphIrq_Active_ExpectAndReturn( UT_HASH_NVIC_IRQ, NVIC_REQUEST_OK );
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
 *        interrupt handler and the DMA configuration.
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
    UtHash_Expect_IrqLine( NVIC_FUNCTION_INACTIVE, NULL );
    UtHash_Expect_IsrRegistration();
#if defined(STM32H7RS)
    Gpdma_Get_DefaultConfig_ExpectAnyArgsAndReturn( GPDMA_REQUEST_OK );
    Gpdma_Init_ExpectAnyArgsAndReturn( GPDMA_REQUEST_OK );
    Gpdma_Init_AddCallback( UtHash_GpdmaInitStub );
    Gpdma_Set_InterruptActive_ExpectAndReturn( UT_HASH_DMA_PERIPH, UT_HASH_DMA_CHANNEL, GPDMA_REQUEST_OK );
#else
    Dma_Get_DefaultConfig_ExpectAnyArgsAndReturn( DMA_REQUEST_OK );
    Dma_Init_ExpectAnyArgsAndReturn( DMA_REQUEST_OK );
    Dma_Init_AddCallback( UtHash_DmaInitStub );
    Dma_Set_TransferErrorIrqActive_ExpectAndReturn( UT_HASH_DMA_PERIPH, UT_HASH_DMA_CHANNEL, DMA_REQUEST_OK );
    Dma_Set_TransferCompleteIrqActive_ExpectAndReturn( UT_HASH_DMA_PERIPH, UT_HASH_DMA_CHANNEL, DMA_REQUEST_OK );
    Dma_Set_InterruptActive_ExpectAndReturn( UT_HASH_DMA_PERIPH, UT_HASH_DMA_CHANNEL, DMA_REQUEST_OK );
#endif /* STM32H7RS */

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );
}


/**
 * \brief Sets up the DMA mock expectations of one DMA chunk: block size in bytes, source address, destination
 *        address and the channel start (Gpdma), or memory address, count of the 32-bit data items and the stream
 *        start (Dma).
 *
 * \param chunkSize [in]: Expected chunk size in bytes
 * \param srcAddr   [in]: Expected source address, NULL for the copy of the trailing bytes in the module (not checked)
 */
static void UtHash_Expect_DmaChunk( hash_DataCnt_t chunkSize, const hash_Data_t * const srcAddr )
{
#if defined(STM32H7RS)
    Gpdma_Set_BlockSize_ExpectAndReturn( UT_HASH_DMA_PERIPH,
                                         UT_HASH_DMA_CHANNEL,
                                         (gpdma_BlockSize_t)chunkSize,
                                         GPDMA_REQUEST_OK );
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
#else
    Dma_Set_MemoryAddr_ExpectAndReturn( UT_HASH_DMA_PERIPH,
                                        UT_HASH_DMA_CHANNEL,
                                        (dma_MemoryAddr_t)(uintptr_t)srcAddr,
                                        DMA_REQUEST_OK );

    if( NULL == srcAddr )
    {
        Dma_Set_MemoryAddr_IgnoreArg_memoryAddr();
    }
    else
    {
        /* The source address of the message is checked */
    }

    Dma_Set_DataCount_ExpectAndReturn( UT_HASH_DMA_PERIPH,
                                       UT_HASH_DMA_CHANNEL,
                                       (dma_DataCount_t)( chunkSize / UT_HASH_DMA_ITEM_SIZE ),
                                       DMA_REQUEST_OK );
    Dma_Set_TransferActive_ExpectAndReturn( UT_HASH_DMA_PERIPH, UT_HASH_DMA_CHANNEL, DMA_REQUEST_OK );
#endif /* STM32H7RS */
}


/**
 * \brief Sets up the DMA mock expectation of the stop of the DMA channel by Hash_Set_Abort().
 */
static void UtHash_Expect_DmaStop( void )
{
#if defined(STM32H7RS)
    Gpdma_Set_ChannelInactive_ExpectAndReturn( UT_HASH_DMA_PERIPH, UT_HASH_DMA_CHANNEL, GPDMA_REQUEST_OK );
#else
    Dma_Set_TransferInactive_ExpectAndReturn( UT_HASH_DMA_PERIPH, UT_HASH_DMA_CHANNEL, DMA_REQUEST_OK );
#endif /* STM32H7RS */
}


/**
 * \brief Sets up the DMA mock expectations of the release of the DMA channel by Hash_Deinit(): the channel is stopped
 *        and the interrupt line of the channel deactivated.
 */
static void UtHash_Expect_DmaRelease( void )
{
#if defined(STM32H7RS)
    Gpdma_Deinit_ExpectAndReturn( UT_HASH_DMA_PERIPH, UT_HASH_DMA_CHANNEL, GPDMA_REQUEST_OK );
    Gpdma_Set_InterruptInactive_ExpectAndReturn( UT_HASH_DMA_PERIPH, UT_HASH_DMA_CHANNEL, GPDMA_REQUEST_OK );
#else
    Dma_Set_TransferInactive_ExpectAndReturn( UT_HASH_DMA_PERIPH, UT_HASH_DMA_CHANNEL, DMA_REQUEST_OK );
    Dma_Set_InterruptInactive_ExpectAndReturn( UT_HASH_DMA_PERIPH, UT_HASH_DMA_CHANNEL, DMA_REQUEST_OK );
#endif /* STM32H7RS */
}


/** \brief Calls the transfer complete callback of the DMA channel captured from the DMA initialization. */
static void UtHash_Call_DmaComplete( void )
{
#if defined(STM32H7RS)
    utHash_DmaConfig.TransferCompleteIsr();
#else
    utHash_DmaConfig.TransferCompleteCallback();
#endif /* STM32H7RS */
}


/** \brief Calls the transfer error callback of the DMA channel captured from the DMA initialization. */
static void UtHash_Call_DmaError( void )
{
#if defined(STM32H7RS)
    utHash_DmaConfig.ErrorIsr( GPDMA_ERROR_TRANSFER );
#else
    utHash_DmaConfig.TransferErrorCallback();
#endif /* STM32H7RS */
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


#if defined(STM32H7RS)
/** \brief Gpdma_Init() callback: copies the configuration and the transfer configuration it points to. */
static gpdma_RequestState_t UtHash_GpdmaInitStub( gpdma_ConfigStruct_t * const configStruct, int callCnt )
{
    ( void )callCnt;

    utHash_DmaConfig = *configStruct;
    utHash_DmaXfer   = *configStruct->TransferConfig;

    return ( GPDMA_REQUEST_OK );
}
#else
/** \brief Dma_Init() callback: copies the configuration. */
static dma_RequestState_t UtHash_DmaInitStub( dma_ConfigStruct_t * const configStruct, int callCnt )
{
    ( void )callCnt;

    utHash_DmaConfig = *configStruct;

    return ( DMA_REQUEST_OK );
}


/** \brief Interrupt handler of another module (the Rng module) owning the interrupt line HASH_RNG, never called. */
static void UtHash_OtherIsr( void )
{
    /* Only its address is compared */
}
#endif /* STM32H7RS */

#endif /* HASH */
