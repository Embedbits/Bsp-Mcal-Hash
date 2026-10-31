/**
 * \author Mr.Nobody
 * \file Hash_Types.h
 * \ingroup Hash
 * \brief Hash module global types definition
 *
 * This file contains the types definitions used across the module and are
 * available for other modules through Port file.
 *
 */

/**
 * \defgroup Hash Hash
 * \brief Hash module
 */

#ifndef HASH_HASH_TYPES_H
#define HASH_HASH_TYPES_H
/* ============================== INCLUDES ================================== */
#include "stdint.h"                         /* Module types definition        */
#include "Gpdma_Port.h"                     /* DMA channel/priority types used by Hash_Config_t */
/* ========================== SYMBOLIC CONSTANTS ============================ */

/** Null pointer definition */
#define HASH_NULL_PTR                        ( ( void* ) 0u )

/** Size in bytes of the opaque \ref hash_Context_t storage (HASH_CR, HASH_STR,
 *  HASH_IMR and all HASH_CSRx context swap registers, see \ref Hash_Get_Context) */
#define HASH_CONTEXT_SIZE                    ( 432u )

/* ========================== EXPORTED MACROS =============================== */

/* ============================== TYPEDEFS ================================== */

/** \brief Type signaling major version of SW module */
typedef uint8_t hash_MajorVersion_t;


/** \brief Type signaling minor version of SW module */
typedef uint8_t hash_MinorVersion_t;


/** \brief Type signaling patch version of SW module */
typedef uint8_t hash_PatchVersion_t;


/** \brief Type signaling actual version of SW module */
typedef struct
{
    hash_MajorVersion_t Major; /**< Major version */
    hash_MinorVersion_t Minor; /**< Minor version */
    hash_PatchVersion_t Patch; /**< Patch version */
}   hash_ModuleVersion_t;


/** \brief Function status enumeration */
typedef enum
{
    HASH_FUNCTION_INACTIVE = 0u, /**< Function status is inactive */
    HASH_FUNCTION_ACTIVE         /**< Function status is active   */
}   hash_FunctionState_t;


/** \brief Flag states enumeration */
typedef enum
{
    HASH_FLAG_INACTIVE = 0u, /**< Inactive flag state */
    HASH_FLAG_ACTIVE         /**< Active flag state   */
}   hash_FlagState_t;


/** \brief Enumeration used to signal request processing state */
typedef enum
{
    HASH_REQUEST_ERROR = 0u, /**< Processing request failed  */
    HASH_REQUEST_OK          /**< Processing request succeed */
}   hash_RequestState_t;


/** \brief Peripheral identification */
typedef enum
{
    HASH_PERIPH_1 = 0u, /**< Hash processor peripheral      */
    HASH_PERIPH_CNT     /**< Count of available peripherals */
}   hash_PeriphId_t;


/** \brief Byte type used for the message, the key and the digest buffers */
typedef uint8_t hash_Data_t;


/** \brief Type used to store a byte count (message, key or digest length) */
typedef uint32_t hash_DataCnt_t;


/** \brief Interrupt priority type definition */
typedef uint32_t hash_IrqPrio_t;


/** \brief Algorithm selection.
 *
 * Not every algorithm is supported by every device, \ref Hash_Get_Capability
 * tells in advance which ones are. A request for an unsupported algorithm
 * returns \ref HASH_REQUEST_ERROR and does not touch the hardware.
 */
typedef enum
{
    HASH_ALGO_MD5 = 0u,     /**< MD5 (128-bit digest)                           */
    HASH_ALGO_SHA1,         /**< SHA-1 (160-bit digest)                         */
    HASH_ALGO_SHA2_224,     /**< SHA2-224 (224-bit digest)                      */
    HASH_ALGO_SHA2_256,     /**< SHA2-256 (256-bit digest)                      */
    HASH_ALGO_SHA2_384,     /**< SHA2-384 (384-bit digest)                      */
    HASH_ALGO_SHA2_512,     /**< SHA2-512 (512-bit digest)                      */
    HASH_ALGO_SHA2_512_224, /**< SHA2-512/224 truncated output (224-bit digest) */
    HASH_ALGO_SHA2_512_256, /**< SHA2-512/256 truncated output (256-bit digest) */
    HASH_ALGO_SHA3_224,     /**< SHA3-224 (224-bit digest)                      */
    HASH_ALGO_SHA3_256,     /**< SHA3-256 (256-bit digest)                      */
    HASH_ALGO_SHA3_384,     /**< SHA3-384 (384-bit digest)                      */
    HASH_ALGO_SHA3_512,     /**< SHA3-512 (512-bit digest)                      */
    HASH_ALGO_SHAKE128,     /**< SHAKE128 extendable output function            */
    HASH_ALGO_SHAKE256,     /**< SHAKE256 extendable output function            */
    HASH_ALGO_CNT           /**< Count of available options                     */
}   hash_Algorithm_t;


/** \brief Plain hash or keyed HMAC selection */
typedef enum
{
    HASH_MODE_HASH = 0u, /**< Plain message digest              */
    HASH_MODE_HMAC,      /**< Keyed-hash message authentication */
    HASH_MODE_CNT        /**< Count of available options        */
}   hash_Mode_t;


/** \brief Data transfer handling style enumeration */
typedef enum
{
    HASH_XFER_MODE_POLL = 0u, /**< Input FIFO is polled by \ref Hash_Task                        */
    HASH_XFER_MODE_ISR,       /**< Input FIFO and digest ready events use the HASH interrupt     */
    HASH_XFER_MODE_DMA,       /**< Input buffer is transferred by Gpdma, completion by interrupt */
    HASH_XFER_MODE_CNT        /**< Count of available options                                    */
}   hash_XferMode_t;


/** \brief Request processing state of the peripheral */
typedef enum
{
    HASH_STATE_IDLE = 0u, /**< No request is being processed                */
    HASH_STATE_BUSY,      /**< A request is being processed                 */
    HASH_STATE_ERROR,     /**< The last request ended with a transfer error */
    HASH_STATE_CNT        /**< Count of available options                   */
}   hash_State_t;


/** \brief List of transfer errors (bit mask) */
typedef enum
{
    HASH_XFER_ERROR_NONE        = 0x00u, /**< No active error mask              */
    HASH_XFER_ERROR_DMA         = 0x01u, /**< DMA transfer error                */
    HASH_XFER_ERROR_OVERRUN     = 0x02u, /**< Input FIFO overrun                */
    HASH_XFER_ERROR_WRONG_STATE = 0x04u, /**< Request issued in the wrong state */
    HASH_XFER_ERROR_ALL         = 0x07u  /**< All possible errors               */
}   hash_XferError_t;


/** \brief Opaque storage of a suspended incremental calculation, allocated by the
 *  application and passed to \ref Hash_Get_Context / \ref Hash_Set_Context. Valid
 *  only for the algorithm, the mode and the device it was taken on. */
typedef struct
{
    uint32_t Value[ HASH_CONTEXT_SIZE / sizeof( uint32_t ) ]; /**< Opaque register image */
}   hash_Context_t;


/** \brief Request completion callback (ISR / DMA mode) */
typedef void ( hash_CompleteCallback_t )( void );


/** \brief Active transfer error callback (ISR / DMA mode) */
typedef void ( hash_ErrorCallback_t )( hash_XferError_t xferError );


/** \brief Type used to store Hash module configuration (see \ref Hash_Init) */
typedef struct
{
    hash_XferMode_t           XferMode;         /**< Data transfer mode (poll / interrupt / DMA)         */
    gpdma_PeriphId_t          DmaPeriphId;      /**< Gpdma controller identification (DMA mode only)     */
    gpdma_ChannelId_t         DmaChannelId;     /**< Gpdma channel identification (DMA mode only)        */
    gpdma_Priority_t          DmaChannelPrio;   /**< Gpdma channel priority (DMA mode only)              */
    hash_IrqPrio_t            IrqPriority;      /**< HASH interrupt priority (ISR / DMA mode)            */
    hash_CompleteCallback_t * CompleteCallback; /**< Completion callback, \ref HASH_NULL_PTR disables it */
    hash_ErrorCallback_t    * ErrorCallback;    /**< Error callback, \ref HASH_NULL_PTR disables it      */
}   hash_Config_t;


/** \brief Parameters of a one-shot digest / HMAC request (see \ref Hash_Set_Calculate) */
typedef struct
{
    hash_Algorithm_t   Algorithm;  /**< Algorithm selection                                             */
    hash_Mode_t        Mode;       /**< Plain hash or HMAC selection                                    */
    const hash_Data_t *Key;        /**< HMAC key, ignored for \ref HASH_MODE_HASH                       */
    hash_DataCnt_t     KeySize;    /**< HMAC key size in bytes, ignored for \ref HASH_MODE_HASH         */
    const hash_Data_t *Input;      /**< Message buffer                                                  */
    hash_DataCnt_t     InputSize;  /**< Message size in bytes                                           */
    hash_Data_t       *Digest;     /**< Output digest buffer                                            */
    hash_DataCnt_t     DigestSize; /**< Output digest buffer size in bytes (requested length for SHAKE) */
}   hash_Request_t;


/** \brief Parameters of an incremental request without the message (see \ref Hash_Set_Start) */
typedef struct
{
    hash_Algorithm_t   Algorithm; /**< Algorithm selection                                     */
    hash_Mode_t        Mode;      /**< Plain hash or HMAC selection                            */
    const hash_Data_t *Key;       /**< HMAC key, ignored for \ref HASH_MODE_HASH               */
    hash_DataCnt_t     KeySize;   /**< HMAC key size in bytes, ignored for \ref HASH_MODE_HASH */
}   hash_StartConfig_t;

/* ========================== EXPORTED VARIABLES ============================ */

/* ========================= EXPORTED FUNCTIONS ============================= */


#endif /* HASH_HASH_TYPES_H */
