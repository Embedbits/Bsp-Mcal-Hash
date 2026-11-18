#======================== Unit tests configuration ============================#
# Unit tests of Hash module. Registered in module CMakeLists.txt by
# UnitTesting_AddPath() and created by UnitTesting_Generate() in "UnitTest"
# build (see EmBi_Platform/CMake/UnitTesting/README.md).

get_filename_component(HASH_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
get_filename_component(MCAL_DIR "${HASH_DIR}/.." ABSOLUTE)

# Both DMA mocks are generated (the test runner includes every Mock*.h of the test file): the DMA streams
# do not exist on STM32H7R / STM32H7S - an empty Dma_Port.h is mocked there
if(MCU_FAMILY_ID STREQUAL "STM32H7RSxx")
    set(UT_DMA_MOCK_HEADER ${MCAL_DIR}/Dma/Tests/UnitTests/Stub/Dma_Port.h)
else()
    set(UT_DMA_MOCK_HEADER ${MCAL_DIR}/Dma/Dma_Port.h)
endif()

# HASH_SR.DINIS / HASH_SR.DCIS are preset by the tests (RegMem is plain memory,
# the HASH core never actually computes a digest) instead of using a HW model.
UnitTesting_Add_Test(
    NAME            Hash
    TEST_SOURCE     Test_Hash.c
    UUT_SOURCES     ${HASH_DIR}/Hash.c
                    ${HASH_DIR}/Hash_Reg.c
    MOCK_HEADERS    ${MCAL_DIR}/Rcc/Rcc_Port.h
                    ${MCAL_DIR}/Nvic/Nvic_Port.h
                    ${UT_DMA_MOCK_HEADER}
                    ${MCAL_DIR}/Gpdma/Gpdma_Port.h          # GPDMA (STM32H7R / STM32H7S)
    INCLUDE_DIRS    ${HASH_DIR}
                    ${MCAL_DIR}/Rcc
                    ${MCAL_DIR}/Nvic
                    ${MCAL_DIR}/Dma
                    ${MCAL_DIR}/Gpdma
    LINK_LIBS       ut_RegMem                           # Registers in host memory
                    ut_CmsisHost                        # CMSIS core intrinsics on host
    FORCE_INCLUDES  ${UNIT_TESTING_CMSIS_HOST_HEADER}   # Replaces cmsis_gcc.h
    HOST_LIBS       Ral_Lib                             # ST LL compiled for host
    COVERAGE_EXCLUDE ".*/Ral/.*"
    RUN_SERIAL
)
