#======================== Unit tests configuration ============================#
# Unit tests of Hash module. Registered in module CMakeLists.txt by
# UnitTesting_AddPath() and created by UnitTesting_Generate() in "UnitTest"
# build (see EmBi_Platform/CMake/UnitTesting/README.md).

get_filename_component(HASH_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
get_filename_component(MCAL_DIR "${HASH_DIR}/.." ABSOLUTE)

# HASH_SR.DINIS / HASH_SR.DCIS are preset by the tests (RegMem is plain memory,
# the HASH core never actually computes a digest) instead of using a HW model.
UnitTesting_Add_Test(
    NAME            Hash
    TEST_SOURCE     Test_Hash.c
    UUT_SOURCES     ${HASH_DIR}/Hash.c
                    ${HASH_DIR}/Hash_Reg.c
    MOCK_HEADERS    ${MCAL_DIR}/Rcc/Rcc_Port.h
                    ${MCAL_DIR}/Nvic/Nvic_Port.h
                    ${MCAL_DIR}/Gpdma/Gpdma_Port.h
    INCLUDE_DIRS    ${HASH_DIR}
                    ${MCAL_DIR}/Rcc
                    ${MCAL_DIR}/Nvic
                    ${MCAL_DIR}/Gpdma
    LINK_LIBS       ut_RegMem                           # Registers in host memory
                    ut_CmsisHost                        # CMSIS core intrinsics on host
    FORCE_INCLUDES  ${UNIT_TESTING_CMSIS_HOST_HEADER}   # Replaces cmsis_gcc.h
    HOST_LIBS       Ral_Lib                             # ST LL compiled for host
    COVERAGE_EXCLUDE ".*/Ral/.*"
    RUN_SERIAL
)
