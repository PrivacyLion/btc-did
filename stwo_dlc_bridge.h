#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

extern "C" {

char *generate_stwo_proof(const char *circuit, const char *input_hash, const char *output_hash);

void free_proof(char *ptr);

char *create_dlc_contract(const char *outcome,
                          const double *payout,
                          int payout_len,
                          const char *oracle);

void free_contract(char *ptr);

char *sign_dlc_outcome(const char *outcome);

void free_signature(char *ptr);

}  // extern "C"
