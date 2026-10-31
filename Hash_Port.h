/**
 * \author Mr.Nobody
 * \file Hash_Port.h
 * \ingroup Hash
 * \brief Hash module public functionality
 *
 * This file contains all available public functionality, any other files shall
 * not used outside of the module.
 *
 */

#ifndef HASH_HASH_PORT_H
#define HASH_HASH_PORT_H

#ifdef __cplusplus
extern "C" {
#endif

/* ============================== INCLUDES ================================== */
#include "Hash_Types.h"                     /* Module types definition        */
/* ============================== TYPEDEFS ================================== */

/* ========================== SYMBOLIC CONSTANTS ============================ */

/* ========================== EXPORTED MACROS =============================== */

/* ========================== EXPORTED VARIABLES ============================ */

/* ========================= EXPORTED FUNCTIONS ============================= */

hash_ModuleVersion_t        Hash_Get_ModuleVersion          ( void );

hash_RequestState_t         Hash_Init                       ( const hash_Config_t * const hashConfig );
hash_RequestState_t         Hash_Deinit                     ( void );
void                        Hash_Task                       ( void );

hash_RequestState_t         Hash_Get_DefaultConfig          ( hash_Config_t * const hashConfig );

/* ------------------------- Capability and state --------------------------- */

hash_RequestState_t         Hash_Get_Capability             ( hash_Algorithm_t algorithm,
                                                              hash_FunctionState_t * const supported );
hash_RequestState_t         Hash_Get_DigestSize             ( hash_Algorithm_t algorithm,
                                                              hash_DataCnt_t * const digestSize );
hash_RequestState_t         Hash_Get_State                  ( hash_State_t * const hashState );
hash_RequestState_t         Hash_Get_XferError               ( hash_XferError_t * const xferError );

/* --------------------------------- One-shot -------------------------------- */

hash_RequestState_t         Hash_Set_Calculate              ( const hash_Request_t * const request );

/* -------------------------------- Incremental ------------------------------ */

hash_RequestState_t         Hash_Set_Start                  ( const hash_StartConfig_t * const startConfig );
hash_RequestState_t         Hash_Set_Update                 ( const hash_Data_t * const data, hash_DataCnt_t dataSize );
hash_RequestState_t         Hash_Set_Finish                 ( hash_Data_t * const digest, hash_DataCnt_t digestSize );
hash_RequestState_t         Hash_Set_Abort                  ( void );

/* ---------------------------- Suspend and resume --------------------------- */

hash_RequestState_t         Hash_Get_Context                ( hash_Context_t * const context );
hash_RequestState_t         Hash_Set_Context                ( const hash_Context_t * const context );

/* -------------------------------- Interrupts ------------------------------- */

hash_RequestState_t         Hash_Set_IrqPriority             ( hash_IrqPrio_t irqPrio );
hash_RequestState_t         Hash_Get_IrqPriority             ( hash_IrqPrio_t * const irqPrio );

#ifdef __cplusplus
}
#endif

#endif /* HASH_HASH_PORT_H */
