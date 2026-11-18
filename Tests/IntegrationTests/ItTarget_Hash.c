/**
 * \author Mr.Nobody
 * \file ItTarget_Hash.c
 * \ingroup Hash
 * \brief Target interface of Hash integration tests (IntegrationTesting_Target.h).
 *
 * The integration testing framework is independent of the target - this file
 * provides everything target specific of the test firmware:
 *  - entry point BspMain() called by StartUp, which runs the tests
 *  - ItTarget_Init() executed on every boot (one test case per boot)
 *  - fault handlers reporting faults by IntegrationTesting_ReportFault()
 *  - ItTarget_SystemReset() executed between the test cases
 *
 * Implementation for Cortex-M (ARMv7-M / ARMv8-M main) with EmBi NVIC module.
 * StartUp has already initialized the vector table in RAM (Nvic_Init) and the
 * default clock (Rcc_Init) before BspMain().
 */

/* ============================= INCLUDES =================================== */
#include "IntegrationTesting.h"             /* Integration testing on target  */
#include "IntegrationTesting_Target.h"      /* Target interface (self)        */
#include "stdlib.h"                         /* abort() replaced by the target */
#include "BspMain.h"                        /* Entry point called by StartUp  */
#include "Nvic_Port.h"                      /* Fault handlers, system reset   */
/* ============================= TYPEDEFS =================================== */

/* ======================= FORWARD DECLARATIONS ============================= */

static void itTarget_FreezeInDebug      ( void );
static void itTarget_SetFaultHandlers   ( void );
static void itTarget_FaultEntry         ( void );
static void itTarget_FaultReport        ( const uint32_t * const stackFrame, uint32_t excNumber );

/* ========================= SYMBOLIC CONSTANTS ============================= */

/** Index of stacked LR in exception stack frame (R0, R1, R2, R3, R12, LR, PC, xPSR) */
#define IT_TARGET_STACK_FRAME_LR            ( 5u )

/** Index of stacked PC in exception stack frame */
#define IT_TARGET_STACK_FRAME_PC            ( 6u )

/** Count of exception names (exception numbers 0 - 7) */
#define IT_TARGET_EXCEPTION_NAME_CNT        ( 8u )

/** CFSR MMARVALID - MMFAR holds address of MemManage fault */
#define IT_TARGET_CFSR_MMARVALID            ( 1u << 7u )

/** CFSR BFARVALID - BFAR holds address of BusFault */
#define IT_TARGET_CFSR_BFARVALID            ( 1u << 15u )

/** Maximal count of registers reported with fault */
#define IT_TARGET_FAULT_REG_CNT             ( 6u )

/* ============================== MACROS ==================================== */

/* ========================== LOCAL VARIABLES =============================== */

/** Names of faults indexed by exception number */
static const char* const itTarget_ExceptionNameLut[ IT_TARGET_EXCEPTION_NAME_CNT ] =
{
    "Exception",                            /* 0 - not a fault                */
    "Exception",                            /* 1 - reset                      */
    "NMI",                                  /* 2                              */
    "HardFault",                            /* 3                              */
    "MemManage",                            /* 4                              */
    "BusFault",                             /* 5                              */
    "UsageFault",                           /* 6                              */
    "SecureFault"                           /* 7 - ARMv8-M main only          */
};

/** Core exceptions reported as failure of the test case */
static const nvic_CoreIrqList_t itTarget_FaultIrqLut[] =
{
    NVIC_CORE_IRQ_NMI,
    NVIC_CORE_IRQ_HARDFAULT,
    NVIC_CORE_IRQ_MEMFAULT,
    NVIC_CORE_IRQ_BUSFAULT,
    NVIC_CORE_IRQ_USAGEFAULT,
#if defined(__ARM_ARCH_8M_MAIN__)
    NVIC_CORE_IRQ_SECUREFAULT,
#endif
};

/** Count of core exceptions reported as failure */
#define IT_TARGET_FAULT_IRQ_CNT             ( sizeof( itTarget_FaultIrqLut ) / sizeof( itTarget_FaultIrqLut[ 0u ] ) )

/* ======================== EXPORTED FUNCTIONS ============================== */

/**
 * \brief Entry point of the test firmware (called by StartUp).
 */
void BspMain( void )
{
    IntegrationTesting_Run();
}


/**
 * \brief Initialization of the target on every boot (IntegrationTesting_Target.h).
 *
 * Initializes everything the tests of Hash need (clocks, pins, ...).
 */
void ItTarget_Init( void )
{
    itTarget_FreezeInDebug();

    itTarget_SetFaultHandlers();
}


/**
 * \brief Resets the target between the test cases (IntegrationTesting_Target.h).
 */
void ItTarget_SystemReset( void )
{
    Nvic_Set_SystemReset();

    for( ;; )
    {
        /* Reset is in progress */
    }
}


/**
 * \brief Abnormal termination (replaces abort() of the C library).
 *
 * abort() of the C library raises SIGABRT by system calls _kill() / _getpid(),
 * which are not available on the target (nosys stubs, linker warnings). It is
 * linked even without explicit call - Unity uses setjmp(), which pulls the ARM
 * unwinder calling abort(). The abort is reported to the framework as a fault
 * of the running test case (address of the caller in LR).
 */
void abort( void )
{
    const integrationTesting_FaultReg_t faultReg = { "LR", (uint32_t)__builtin_return_address( 0u ) };

    IntegrationTesting_ReportFault( "abort", &faultReg, 1u );

    for( ;; )
    {
        /* Fault is reported, the framework resets the target */
    }
}

/* ========================== LOCAL FUNCTIONS =============================== */

/**
 * \brief Stops peripherals used by the tests while the core is halted.
 *
 * The host (probe-rs) halts the core for a few milliseconds on every access of
 * the mailbox. Timers, watchdogs, RTC and I2C timeouts used by the tests shall
 * be stopped during the halt (DBGMCU), so time measurements stay consistent.
 * Example (STM32, Stm32_system.h):
 *
 * \code
 * LL_DBGMCU_APB1_GRP1_FreezePeriph( LL_DBGMCU_APB1_GRP1_TIM2_STOP | LL_DBGMCU_APB1_GRP1_IWDG_STOP );
 * \endcode
 */
static void itTarget_FreezeInDebug( void )
{
    /* No peripheral of the tests depends on time */
}


/**
 * \brief Routes fault exceptions to \ref itTarget_FaultEntry.
 */
static void itTarget_SetFaultHandlers( void )
{
    for( uint32_t faultIdx = 0u; IT_TARGET_FAULT_IRQ_CNT > faultIdx; faultIdx++ )
    {
        (void)Nvic_Set_CoreIrq_Handler( itTarget_FaultIrqLut[ faultIdx ], itTarget_FaultEntry );
    }
}


/**
 * \brief Entry of fault exceptions - passes stack frame and exception number
 *        to \ref itTarget_FaultReport.
 *
 * \note Stack frame is on MSP or PSP according to EXC_RETURN (LR bit 2).
 */
__attribute__((naked))
static void itTarget_FaultEntry( void )
{
    __asm volatile
    (
        "tst    lr, #4                              \n"
        "ite    eq                                  \n"
        "mrseq  r0, msp                             \n"
        "mrsne  r0, psp                             \n"
        "mrs    r1, ipsr                            \n"
        "b      itTarget_FaultReport                \n"
    );
}


/**
 * \brief Collects fault registers and reports the fault to the framework.
 *
 * \param stackFrame [in]: Exception stack frame (R0, R1, R2, R3, R12, LR, PC, xPSR)
 * \param excNumber  [in]: Exception number (IPSR)
 */
__attribute__((used, noinline))
static void itTarget_FaultReport( const uint32_t * const stackFrame, uint32_t excNumber )
{
    nvic_FaultStatus_t              faultStatus = { 0u };
    integrationTesting_FaultReg_t   faultRegs[ IT_TARGET_FAULT_REG_CNT ];
    uint32_t                        faultRegCnt = 0u;
    const char*                     faultName   = itTarget_ExceptionNameLut[ 0u ];

    if( IT_TARGET_EXCEPTION_NAME_CNT > excNumber )
    {
        faultName = itTarget_ExceptionNameLut[ excNumber ];
    }
    else
    {
        /* Unknown exception - generic name */
    }

    (void)Nvic_Get_FaultStatus( &faultStatus );

    faultRegs[ faultRegCnt++ ] = (integrationTesting_FaultReg_t){ "PC",   stackFrame[ IT_TARGET_STACK_FRAME_PC ] };
    faultRegs[ faultRegCnt++ ] = (integrationTesting_FaultReg_t){ "LR",   stackFrame[ IT_TARGET_STACK_FRAME_LR ] };
    faultRegs[ faultRegCnt++ ] = (integrationTesting_FaultReg_t){ "CFSR", faultStatus.Cfsr };
    faultRegs[ faultRegCnt++ ] = (integrationTesting_FaultReg_t){ "HFSR", faultStatus.Hfsr };

    if( 0u != ( faultStatus.Cfsr & IT_TARGET_CFSR_MMARVALID ) )
    {
        faultRegs[ faultRegCnt++ ] = (integrationTesting_FaultReg_t){ "MMFAR", faultStatus.Mmfar };
    }
    else
    {
        /* MemManage fault address is not valid */
    }

    if( 0u != ( faultStatus.Cfsr & IT_TARGET_CFSR_BFARVALID ) )
    {
        faultRegs[ faultRegCnt++ ] = (integrationTesting_FaultReg_t){ "BFAR", faultStatus.Bfar };
    }
    else
    {
        /* BusFault address is not valid */
    }

    IntegrationTesting_ReportFault( faultName, faultRegs, faultRegCnt );
}

/* =============================== TASKS ==================================== */
