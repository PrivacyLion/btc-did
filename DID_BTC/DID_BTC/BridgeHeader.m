#ifndef BRIDGE_HEADER_H
#define BRIDGE_HEADER_H

#ifdef __cplusplus
extern "C" {
#endif

// STWO Proof Functions
char* generate_stwo_proof(const char* circuit, const char* input_hash, const char* output_hash);
void free_proof(char* ptr);

// DLC Contract Functions
char* create_dlc_contract(const char* outcome, const double* payout, int payout_len, const char* oracle);
void free_contract(char* ptr);

// DLC Signing Functions
char* sign_dlc_outcome(const char* outcome);
void free_signature(char* ptr);

#ifdef __cplusplus
}
#endif

#endif // BRIDGE_HEADER_H
