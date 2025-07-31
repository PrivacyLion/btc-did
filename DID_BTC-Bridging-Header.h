#ifndef DID_BTC_BRIDGING_HEADER_H
#define DID_BTC_BRIDGING_HEADER_H

#ifdef __cplusplus
extern "C" {
#endif

char *generate_stwo_proof(const char *circuit, const char *input_hash, const char *output_hash);
void free_proof(char *ptr);

char *create_dlc_contract(const char *outcome, const double *payout, int payout_len, const char *oracle);
void free_contract(char *ptr);

char *sign_dlc_outcome(const char *outcome);
void free_signature(char *ptr);

#ifdef __cplusplus
}
#endif

#endif // DID_BTC_BRIDGING_HEADER_H
 
