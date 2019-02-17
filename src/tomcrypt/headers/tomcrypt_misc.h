/* ---- LTC_BASE64 Routines ---- */
#ifdef LTC_BASE64
int base64_encode(const unsigned char *in,  unsigned long len,
                        unsigned char *out, unsigned long *outlen);

int base64_decode(const unsigned char *in,  unsigned long len,
                        unsigned char *out, unsigned long *outlen);
#endif

#ifdef LTC_BASE64_URL
int base64url_encode(const unsigned char *in,  unsigned long len,
                        unsigned char *out, unsigned long *outlen);

int base64url_decode(const unsigned char *in,  unsigned long len,
                        unsigned char *out, unsigned long *outlen);
#endif

/* ===> LTC_HKDF -- RFC5869 HMAC-based Key Derivation Function <=== */
#ifdef LTC_HKDF

int hkdf_test(void);

int hkdf_extract(int hash_idx,
                 const unsigned char *salt, unsigned long saltlen,
                 const unsigned char *in,   unsigned long inlen,
                       unsigned char *out,  unsigned long *outlen);

int hkdf_expand(int hash_idx,
                const unsigned char *info, unsigned long infolen,
                const unsigned char *in,   unsigned long inlen,
                      unsigned char *out,  unsigned long outlen);

int hkdf(int hash_idx,
         const unsigned char *salt, unsigned long saltlen,
         const unsigned char *info, unsigned long infolen,
         const unsigned char *in,   unsigned long inlen,
               unsigned char *out,  unsigned long outlen);

#endif  /* LTC_HKDF */

/* ---- MEM routines ---- */
int mem_neq(const void *a, const void *b, size_t len);
void zeromem(volatile void *dst, size_t len);
void burn_stack(unsigned long len);

const char *error_to_string(int err);

extern const char *crypt_build_settings;

/* ---- HMM ---- */
int crypt_fsa(void *mp, ...);

/* ---- Dynamic language support ---- */
int crypt_get_constant(const char* namein, int *valueout);
int crypt_list_all_constants(char *names_list, unsigned int *names_list_size);

int crypt_get_size(const char* namein, unsigned int *sizeout);
int crypt_list_all_sizes(char *names_list, unsigned int *names_list_size);

#ifdef LTM_DESC
void init_LTM(void);
#endif
#ifdef TFM_DESC
void init_TFM(void);
#endif
/*                          *** use of GMP is untested ***
#ifdef GMP_DESC
void init_GMP(void);
#endif
*/


/* $Source$ */
/* $Revision$ */
/* $Date$ */
