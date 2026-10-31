/**
 * \author Mr.Nobody
 * \file ItTest_Hash.c
 * \ingroup Hash
 * \brief Integration tests of the hash processor (HASH) module on target.
 *
 * Hash module runs on the MCU together with real RCC, NVIC and Gpdma modules and
 * hardware. Tests verify the standard test vectors of FIPS 180-4 / RFC 2202
 * (a real digest / HMAC the unit tests, with emulated registers, cannot prove)
 * in POLL mode, the incremental interface and the suspend / resume of a
 * calculation. The DMA mode is checked with the same vectors (one chunk, two
 * chunks with HASH_CR.MDMAT, the empty message), with a flash region longer
 * than one Gpdma block against the POLL mode digest and with the abort of a
 * running transfer.
 *
 * Used resources:
 * - HASH, Gpdma1 channel 0 (DMA mode), no external wiring.
 */

/* ============================= INCLUDES =================================== */
#include "unity.h"                          /* Unity testing framework        */
#include "IntegrationTesting.h"             /* Integration testing on target  */
#include "Hash_Port.h"                      /* Module under test              */
#include "Gpdma_Port.h"                     /* State of the Gpdma channel     */
/* ============================= TYPEDEFS =================================== */

/* ======================= FORWARD DECLARATIONS ============================= */

static void ItHash_Init_Module( void );
static void ItHash_Init_Dma( void );
static void ItHash_Calculate_Dma( const hash_Data_t * const input,
                                  hash_DataCnt_t inputSize,
                                  hash_Data_t * const digest );
static void ItHash_Callback_Complete( void );
static void ItHash_Callback_Error( hash_XferError_t xferError );

/* ========================= SYMBOLIC CONSTANTS ============================= */

/** Size of the SHA-1 digest */
#define IT_HASH_SHA1_DIGEST_SIZE            ( 20u )

/** Byte indices used to split \ref itHash_MsgAbc across several Hash_Set_Update() calls */
#define IT_HASH_ABC_IDX_1                   ( 1u )
#define IT_HASH_ABC_IDX_2                   ( 2u )

/** Size in bytes of the second chunk of \ref itHash_MsgAbc ("bc") */
#define IT_HASH_ABC_REMAINDER_SIZE          ( 2u )

/** FIPS 180-4 test vector: message "abc" */
static const hash_Data_t itHash_MsgAbc[ 3 ] = { 'a', 'b', 'c' };

/** FIPS 180-4 known SHA-1 digest of \ref itHash_MsgAbc, split to keep every line short */
#define IT_HASH_SHA1_ABC_B0_7                0xA9u, 0x99u, 0x3Eu, 0x36u, 0x47u, 0x06u, 0x81u, 0x6Au
#define IT_HASH_SHA1_ABC_B8_15               0xBAu, 0x3Eu, 0x25u, 0x71u, 0x78u, 0x50u, 0xC2u, 0x6Cu
#define IT_HASH_SHA1_ABC_B16_19              0x9Cu, 0xD0u, 0xD8u, 0x9Du

static const hash_Data_t itHash_Sha1Abc[ IT_HASH_SHA1_DIGEST_SIZE ] =
{
    IT_HASH_SHA1_ABC_B0_7,
    IT_HASH_SHA1_ABC_B8_15,
    IT_HASH_SHA1_ABC_B16_19
};

/** RFC 2202 test case 1: HMAC-SHA1 key (20 bytes of 0x0b), split to keep every line short */
#define IT_HASH_HMAC_KEY_BYTE                0x0Bu

static const hash_Data_t itHash_HmacKey[ 20 ] =
{
    IT_HASH_HMAC_KEY_BYTE, IT_HASH_HMAC_KEY_BYTE, IT_HASH_HMAC_KEY_BYTE, IT_HASH_HMAC_KEY_BYTE,
    IT_HASH_HMAC_KEY_BYTE, IT_HASH_HMAC_KEY_BYTE, IT_HASH_HMAC_KEY_BYTE, IT_HASH_HMAC_KEY_BYTE,
    IT_HASH_HMAC_KEY_BYTE, IT_HASH_HMAC_KEY_BYTE, IT_HASH_HMAC_KEY_BYTE, IT_HASH_HMAC_KEY_BYTE,
    IT_HASH_HMAC_KEY_BYTE, IT_HASH_HMAC_KEY_BYTE, IT_HASH_HMAC_KEY_BYTE, IT_HASH_HMAC_KEY_BYTE,
    IT_HASH_HMAC_KEY_BYTE, IT_HASH_HMAC_KEY_BYTE, IT_HASH_HMAC_KEY_BYTE, IT_HASH_HMAC_KEY_BYTE
};

/** RFC 2202 test case 1: message "Hi There" */
static const hash_Data_t itHash_HmacMsg[ 8 ] = { 'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e' };

/** RFC 2202 test case 1: known HMAC-SHA1 digest of \ref itHash_HmacMsg with \ref itHash_HmacKey,
 *  split to keep every line short */
#define IT_HASH_HMAC_SHA1_B0_7                0xB6u, 0x17u, 0x31u, 0x86u, 0x55u, 0x05u, 0x72u, 0x64u
#define IT_HASH_HMAC_SHA1_B8_15               0xE2u, 0x8Bu, 0xC0u, 0xB6u, 0xFBu, 0x37u, 0x8Cu, 0x8Eu
#define IT_HASH_HMAC_SHA1_B16_19              0xF1u, 0x46u, 0xBEu, 0x00u

static const hash_Data_t itHash_HmacSha1Expected[ IT_HASH_SHA1_DIGEST_SIZE ] =
{
    IT_HASH_HMAC_SHA1_B0_7,
    IT_HASH_HMAC_SHA1_B8_15,
    IT_HASH_HMAC_SHA1_B16_19
};

/** Size in bytes of the aborted DMA calculation: long enough that the Gpdma channel still runs at the abort */
#define IT_HASH_DMA_ABORT_SIZE               ( 16384u )

/** Word alignment of the DMA input buffers (the DMA reads the message as 32-bit words) */
#define IT_HASH_WORD_ALIGN                   ( 4u )

/** "abc" in a word-aligned buffer for the DMA mode */
static const hash_Data_t itHash_DmaMsgAbc[ 3 ] __attribute__(( aligned( IT_HASH_WORD_ALIGN ) )) = { 'a', 'b', 'c' };

/** FIPS 180-4 test vector of 448 bits: 48 bytes in a chunk with MDMAT set, 8 trailing bytes in the last chunk */
#define IT_HASH_FIPS56_SIZE                  ( 56u )

static const hash_Data_t itHash_DmaMsgFips56[ IT_HASH_FIPS56_SIZE + 1u ] __attribute__(( aligned( IT_HASH_WORD_ALIGN ) )) =
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

/** FIPS 180-4 known SHA-1 digest of \ref itHash_DmaMsgFips56, split to keep every line short */
#define IT_HASH_SHA1_FIPS56_B0_7             0x84u, 0x98u, 0x3Eu, 0x44u, 0x1Cu, 0x3Bu, 0xD2u, 0x6Eu
#define IT_HASH_SHA1_FIPS56_B8_15            0xBAu, 0xAEu, 0x4Au, 0xA1u, 0xF9u, 0x51u, 0x29u, 0xE5u
#define IT_HASH_SHA1_FIPS56_B16_19           0xE5u, 0x46u, 0x70u, 0xF1u

static const hash_Data_t itHash_Sha1Fips56[ IT_HASH_SHA1_DIGEST_SIZE ] =
{
    IT_HASH_SHA1_FIPS56_B0_7,
    IT_HASH_SHA1_FIPS56_B8_15,
    IT_HASH_SHA1_FIPS56_B16_19
};

/** Known SHA-1 digest of the empty message, split to keep every line short */
#define IT_HASH_SHA1_EMPTY_B0_7              0xDAu, 0x39u, 0xA3u, 0xEEu, 0x5Eu, 0x6Bu, 0x4Bu, 0x0Du
#define IT_HASH_SHA1_EMPTY_B8_15             0x32u, 0x55u, 0xBFu, 0xEFu, 0x95u, 0x60u, 0x18u, 0x90u
#define IT_HASH_SHA1_EMPTY_B16_19            0xAFu, 0xD8u, 0x07u, 0x09u

static const hash_Data_t itHash_Sha1Empty[ IT_HASH_SHA1_DIGEST_SIZE ] =
{
    IT_HASH_SHA1_EMPTY_B0_7,
    IT_HASH_SHA1_EMPTY_B8_15,
    IT_HASH_SHA1_EMPTY_B16_19
};

/** Size in bytes of the flash region hashed in both modes: more than one Gpdma block (65520 bytes),
 *  3 trailing bytes (NBLW = 24), within the 128 KB flash of the smallest line (H503) */
#define IT_HASH_DMA_LONG_SIZE                ( 100003u )

/** Count of polls of the module state while a DMA request runs */
#define IT_HASH_DMA_WAIT_LOOPS               ( 0x400000u )

/* ========================== LOCAL VARIABLES =============================== */

/** Number of completion callbacks of the module */
static volatile uint32_t itHash_CompleteCnt = 0u;

/** Number of error callbacks of the module */
static volatile uint32_t itHash_ErrorCnt = 0u;

/* ============================= TEST SETUP ================================= */

void setUp( void )
{
    /* Nothing to prepare, every test initializes the module itself */
}


void tearDown( void )
{
    (void)Hash_Deinit();
}

/* =============================== TESTS ==================================== */

/**
 * \brief   Hash_Set_Calculate() computes the FIPS 180-4 SHA-1 test vector of "abc".
 *
 * \par Expected results
 * - HASH_REQUEST_OK, the digest equals \ref itHash_Sha1Abc.
 */
void It_Hash_Set_Calculate_Sha1Abc_MatchesKnownDigest( void )
{
    hash_Data_t    digest[ IT_HASH_SHA1_DIGEST_SIZE ];
    hash_Request_t request = { 0 };

    ItHash_Init_Module();

    request.Algorithm  = HASH_ALGO_SHA1;
    request.Mode       = HASH_MODE_HASH;
    request.Input      = itHash_MsgAbc;
    request.InputSize  = sizeof( itHash_MsgAbc );
    request.Digest     = digest;
    request.DigestSize = sizeof( digest );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Calculate( &request ) );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( itHash_Sha1Abc, digest, IT_HASH_SHA1_DIGEST_SIZE );
}


/**
 * \brief   Hash_Set_Calculate() computes the SHA-1 digest of the empty message.
 *
 * \par Expected results
 * - HASH_REQUEST_OK, the digest equals \ref itHash_Sha1Empty (not the digest of four zero bytes).
 */
void It_Hash_Set_Calculate_Sha1Empty_MatchesKnownDigest( void )
{
    hash_Data_t    digest[ IT_HASH_SHA1_DIGEST_SIZE ];
    hash_Request_t request = { 0 };

    ItHash_Init_Module();

    request.Algorithm  = HASH_ALGO_SHA1;
    request.Mode       = HASH_MODE_HASH;
    request.Input      = HASH_NULL_PTR;
    request.InputSize  = 0u;
    request.Digest     = digest;
    request.DigestSize = sizeof( digest );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Calculate( &request ) );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( itHash_Sha1Empty, digest, IT_HASH_SHA1_DIGEST_SIZE );
}


/**
 * \brief   The incremental interface, split across three updates, matches the one-shot digest.
 *
 * \par Expected results
 * - Every call returns HASH_REQUEST_OK, the digest equals \ref itHash_Sha1Abc.
 */
void It_Hash_Incremental_ThreeUpdates_MatchesKnownDigest( void )
{
    hash_Data_t         digest[ IT_HASH_SHA1_DIGEST_SIZE ];
    hash_StartConfig_t  startConfig = { 0 };

    ItHash_Init_Module();

    startConfig.Algorithm = HASH_ALGO_SHA1;
    startConfig.Mode      = HASH_MODE_HASH;

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Start( &startConfig ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Update( &itHash_MsgAbc[ 0 ], 1u ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Update( &itHash_MsgAbc[ IT_HASH_ABC_IDX_1 ], 1u ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Update( &itHash_MsgAbc[ IT_HASH_ABC_IDX_2 ], 1u ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Finish( digest, sizeof( digest ) ) );

    TEST_ASSERT_EQUAL_UINT8_ARRAY( itHash_Sha1Abc, digest, IT_HASH_SHA1_DIGEST_SIZE );
}


/**
 * \brief   Hash_Set_Calculate() computes the RFC 2202 HMAC-SHA1 test case 1.
 *
 * \par Expected results
 * - HASH_REQUEST_OK, the digest equals \ref itHash_HmacSha1Expected.
 */
void It_Hash_Set_Calculate_HmacSha1_MatchesKnownDigest( void )
{
    hash_Data_t    digest[ IT_HASH_SHA1_DIGEST_SIZE ];
    hash_Request_t request = { 0 };

    ItHash_Init_Module();

    request.Algorithm  = HASH_ALGO_SHA1;
    request.Mode        = HASH_MODE_HMAC;
    request.Key          = itHash_HmacKey;
    request.KeySize      = sizeof( itHash_HmacKey );
    request.Input        = itHash_HmacMsg;
    request.InputSize    = sizeof( itHash_HmacMsg );
    request.Digest       = digest;
    request.DigestSize   = sizeof( digest );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Calculate( &request ) );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( itHash_HmacSha1Expected, digest, IT_HASH_SHA1_DIGEST_SIZE );
}


/**
 * \brief   Hash_Set_Abort() stops an open calculation and the peripheral accepts a new one.
 *
 * \par Expected results
 * - HASH_REQUEST_OK for the abort, a following one-shot request still succeeds and
 *   matches the known digest (the hardware was really reinitialized).
 */
void It_Hash_Set_Abort_AllowsNewCalculation( void )
{
    hash_Data_t         digest[ IT_HASH_SHA1_DIGEST_SIZE ];
    hash_StartConfig_t  startConfig = { 0 };
    hash_Request_t      request     = { 0 };

    ItHash_Init_Module();

    startConfig.Algorithm = HASH_ALGO_SHA1;
    startConfig.Mode      = HASH_MODE_HASH;
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Start( &startConfig ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Update( itHash_MsgAbc, sizeof( itHash_MsgAbc ) ) );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Abort() );

    request.Algorithm  = HASH_ALGO_SHA1;
    request.Mode       = HASH_MODE_HASH;
    request.Input      = itHash_MsgAbc;
    request.InputSize  = sizeof( itHash_MsgAbc );
    request.Digest     = digest;
    request.DigestSize = sizeof( digest );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Calculate( &request ) );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( itHash_Sha1Abc, digest, IT_HASH_SHA1_DIGEST_SIZE );
}


/**
 * \brief   Hash_Get_Context() / Hash_Set_Context() suspend and resume a calculation in the
 *          middle of the message without losing the result.
 *
 * \par Expected results
 * - Both calls return HASH_REQUEST_OK, the digest after resume equals \ref itHash_Sha1Abc.
 */
void It_Hash_ContextRoundTrip_FinishesAfterResume( void )
{
    hash_Data_t         digest[ IT_HASH_SHA1_DIGEST_SIZE ];
    hash_Context_t      context;
    hash_StartConfig_t  startConfig = { 0 };

    ItHash_Init_Module();

    startConfig.Algorithm = HASH_ALGO_SHA1;
    startConfig.Mode      = HASH_MODE_HASH;
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Start( &startConfig ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Update( &itHash_MsgAbc[ 0 ], 1u ) );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_Context( &context ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Context( &context ) );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK,
                       Hash_Set_Update( &itHash_MsgAbc[ IT_HASH_ABC_IDX_1 ],
                                        IT_HASH_ABC_REMAINDER_SIZE ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Finish( digest, sizeof( digest ) ) );

    TEST_ASSERT_EQUAL_UINT8_ARRAY( itHash_Sha1Abc, digest, IT_HASH_SHA1_DIGEST_SIZE );
}


/**
 * \brief   Hash_Set_Calculate() in DMA mode computes the FIPS 180-4 SHA-1 test vector of "abc" (3 trailing bytes in
 *          a single one word chunk).
 *
 * \par Expected results
 * - The request ends with one completion callback and no error, the digest equals \ref itHash_Sha1Abc.
 */
void It_Hash_Set_Calculate_DmaSha1Abc_MatchesKnownDigest( void )
{
    hash_Data_t digest[ IT_HASH_SHA1_DIGEST_SIZE ] = { 0u };

    ItHash_Init_Dma();
    ItHash_Calculate_Dma( itHash_DmaMsgAbc, sizeof( itHash_DmaMsgAbc ), digest );

    TEST_ASSERT_EQUAL_UINT8_ARRAY( itHash_Sha1Abc, digest, IT_HASH_SHA1_DIGEST_SIZE );
}


/**
 * \brief   Hash_Set_Calculate() in DMA mode computes the FIPS 180-4 SHA-1 test vector of 448 bits: 48 bytes in a chunk
 *          with HASH_CR.MDMAT set, the 8 trailing bytes in the last chunk.
 *
 * \par Expected results
 * - The request ends with one completion callback and no error, the digest equals \ref itHash_Sha1Fips56.
 */
void It_Hash_Set_Calculate_DmaSha1Fips56_MatchesKnownDigest( void )
{
    hash_Data_t digest[ IT_HASH_SHA1_DIGEST_SIZE ] = { 0u };

    ItHash_Init_Dma();
    ItHash_Calculate_Dma( itHash_DmaMsgFips56, IT_HASH_FIPS56_SIZE, digest );

    TEST_ASSERT_EQUAL_UINT8_ARRAY( itHash_Sha1Fips56, digest, IT_HASH_SHA1_DIGEST_SIZE );
}


/**
 * \brief   Hash_Set_Calculate() in DMA mode computes the SHA-1 digest of the empty message (no transfer, the message is
 *          padded by software and ended by the digest interrupt).
 *
 * \par Expected results
 * - The request ends with one completion callback and no error, the digest equals \ref itHash_Sha1Empty.
 */
void It_Hash_Set_Calculate_DmaSha1Empty_MatchesKnownDigest( void )
{
    hash_Data_t digest[ IT_HASH_SHA1_DIGEST_SIZE ] = { 0u };

    ItHash_Init_Dma();
    ItHash_Calculate_Dma( HASH_NULL_PTR, 0u, digest );

    TEST_ASSERT_EQUAL_UINT8_ARRAY( itHash_Sha1Empty, digest, IT_HASH_SHA1_DIGEST_SIZE );
}


/**
 * \brief   A flash region longer than one Gpdma block gives the same SHA-1 digest in the DMA and in the POLL mode.
 *
 * \details \ref IT_HASH_DMA_LONG_SIZE bytes from the start of the flash: two chunks of the message (65520 bytes with
 *          MDMAT set, the rest with MDMAT set) and the 3 trailing bytes in the last chunk (NBLW = 24).
 *
 * \par Expected results
 * - Both requests succeed, the DMA request ends with one completion callback and no error.
 * - The DMA digest equals the POLL digest.
 */
void It_Hash_Set_Calculate_DmaLongFlash_MatchesPollDigest( void )
{
    hash_Data_t    pollDigest[ IT_HASH_SHA1_DIGEST_SIZE ] = { 0u };
    hash_Data_t    dmaDigest[ IT_HASH_SHA1_DIGEST_SIZE ]  = { 0u };
    hash_Request_t request = { 0 };

    ItHash_Init_Module();

    request.Algorithm  = HASH_ALGO_SHA1;
    request.Mode       = HASH_MODE_HASH;
    request.Input      = (const hash_Data_t *)FLASH_BASE;
    request.InputSize  = IT_HASH_DMA_LONG_SIZE;
    request.Digest     = pollDigest;
    request.DigestSize = sizeof( pollDigest );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Calculate( &request ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Deinit() );

    ItHash_Init_Dma();
    ItHash_Calculate_Dma( (const hash_Data_t *)FLASH_BASE, IT_HASH_DMA_LONG_SIZE, dmaDigest );

    TEST_ASSERT_EQUAL_UINT8_ARRAY( pollDigest, dmaDigest, IT_HASH_SHA1_DIGEST_SIZE );
}


/**
 * \brief   Hash_Set_Abort() stops a running DMA calculation: the Gpdma channel is stopped, the abort is not reported as
 *          a transfer error and the next DMA request works.
 *
 * \details A one-shot SHA-1 calculation over \ref IT_HASH_DMA_ABORT_SIZE bytes of the flash memory is started in
 *          the DMA mode and aborted at once, while the Gpdma channel still feeds the HASH input. The abort suspends
 *          the channel and waits for the suspension flag. A DMA request of "abc" follows on the reset channel.
 *
 * \par Expected results
 * - HASH_REQUEST_OK for the start and the abort.
 * - The Gpdma channel of the module is inactive after the abort.
 * - No error callback, Hash_Get_XferError() reports HASH_XFER_ERROR_NONE.
 * - The following request ends with one completion callback (none from the aborted one) and the digest equals
 *   \ref itHash_Sha1Abc.
 */
void It_Hash_Set_Abort_RunningDma_StopsChannelWithoutError( void )
{
    hash_Data_t           digest[ IT_HASH_SHA1_DIGEST_SIZE ];
    hash_Config_t         config;
    hash_Request_t        request      = { 0 };
    hash_XferError_t      xferError    = HASH_XFER_ERROR_NONE;
    gpdma_FunctionState_t channelState = GPDMA_FUNCTION_ACTIVE;

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_DefaultConfig( &config ) );
    ItHash_Init_Dma();

    request.Algorithm  = HASH_ALGO_SHA1;
    request.Mode       = HASH_MODE_HASH;
    request.Input      = (const hash_Data_t *)FLASH_BASE;
    request.InputSize  = IT_HASH_DMA_ABORT_SIZE;
    request.Digest     = digest;
    request.DigestSize = sizeof( digest );

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Calculate( &request ) );
    TEST_ASSERT_EQUAL( GPDMA_REQUEST_OK,
                       Gpdma_Get_ChannelState( config.DmaPeriphId,
                                               config.DmaChannelId,
                                               &channelState ) );
    TEST_ASSERT_EQUAL_MESSAGE( GPDMA_FUNCTION_ACTIVE, channelState, "DMA finished before the abort" );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Abort() );

    TEST_ASSERT_EQUAL( GPDMA_REQUEST_OK,
                       Gpdma_Get_ChannelState( config.DmaPeriphId,
                                               config.DmaChannelId,
                                               &channelState ) );
    TEST_ASSERT_EQUAL( GPDMA_FUNCTION_INACTIVE, channelState );
    TEST_ASSERT_EQUAL_UINT32( 0u, itHash_ErrorCnt );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_XferError( &xferError ) );
    TEST_ASSERT_EQUAL( HASH_XFER_ERROR_NONE, xferError );

    ItHash_Calculate_Dma( itHash_DmaMsgAbc, sizeof( itHash_DmaMsgAbc ), digest );

    TEST_ASSERT_EQUAL_UINT8_ARRAY( itHash_Sha1Abc, digest, IT_HASH_SHA1_DIGEST_SIZE );
}

/* =========================== LOCAL FUNCTIONS =============================== */

/**
 * \brief Initializes the module in POLL mode for a test case.
 */
static void ItHash_Init_Module( void )
{
    hash_Config_t config;

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_DefaultConfig( &config ) );
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );
}


/**
 * \brief Initializes the module in DMA mode (default Gpdma channel) with both callbacks, the callback counters are
 *        cleared.
 */
static void ItHash_Init_Dma( void )
{
    hash_Config_t config;

    itHash_CompleteCnt = 0u;
    itHash_ErrorCnt    = 0u;

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_DefaultConfig( &config ) );
    config.XferMode         = HASH_XFER_MODE_DMA;
    config.CompleteCallback = ItHash_Callback_Complete;
    config.ErrorCallback    = ItHash_Callback_Error;
    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Init( &config ) );
}


/**
 * \brief Computes the SHA-1 digest of a message in DMA mode and waits for the end of the request.
 *
 * \param input     [in]:  Word-aligned message, may be NULL for the empty message
 * \param inputSize [in]:  Message size in bytes
 * \param digest    [out]: SHA-1 digest (\ref IT_HASH_SHA1_DIGEST_SIZE bytes)
 *
 * The request shall end within \ref IT_HASH_DMA_WAIT_LOOPS polls of the state, as IDLE, with exactly one more
 * completion callback and no error callback.
 */
static void ItHash_Calculate_Dma( const hash_Data_t * const input,
                                  hash_DataCnt_t inputSize,
                                  hash_Data_t * const digest )
{
    hash_Request_t request     = { 0 };
    hash_State_t   hashState   = HASH_STATE_BUSY;
    const uint32_t completeCnt = itHash_CompleteCnt;

    request.Algorithm  = HASH_ALGO_SHA1;
    request.Mode       = HASH_MODE_HASH;
    request.Input      = input;
    request.InputSize  = inputSize;
    request.Digest     = digest;
    request.DigestSize = IT_HASH_SHA1_DIGEST_SIZE;

    TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Set_Calculate( &request ) );

    for( uint32_t loopCnt = 0u; IT_HASH_DMA_WAIT_LOOPS > loopCnt; loopCnt++ )
    {
        TEST_ASSERT_EQUAL( HASH_REQUEST_OK, Hash_Get_State( &hashState ) );

        if( HASH_STATE_BUSY != hashState )
        {
            break;
        }
        else
        {
            /* The request still runs */
        }
    }

    TEST_ASSERT_EQUAL_MESSAGE( HASH_STATE_IDLE, hashState, "DMA request did not end as IDLE" );
    TEST_ASSERT_EQUAL_UINT32( completeCnt + 1u, itHash_CompleteCnt );
    TEST_ASSERT_EQUAL_UINT32( 0u, itHash_ErrorCnt );
}


/**
 * \brief Completion callback of the module, counts the calls.
 */
static void ItHash_Callback_Complete( void )
{
    itHash_CompleteCnt++;
}


/**
 * \brief Error callback of the module, counts the calls.
 *
 * \param xferError [in]: Error mask of the module (not evaluated).
 */
static void ItHash_Callback_Error( hash_XferError_t xferError )
{
    (void)xferError;
    itHash_ErrorCnt++;
}
