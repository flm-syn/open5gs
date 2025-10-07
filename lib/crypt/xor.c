/*
 * 3GPP AKA - Test algorithm (3GPP TS 34.108 8.1.2.1)
 * Copyright 2013-2023 Software Radio Systems Limited
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * This file is srsRAN's implementation of the test authentication 
 * algorithm (XOR 3G) defined for 3GPP AKA.
 */

#include "ogs-crypt.h"

#include "xor.h"

/**
 * xor_generate - Generate AKA AUTN,IK,CK,RES
 * @opc: OPc = not used
 * @amf: AMF = 16-bit authentication management field
 * @k: K = 128-bit subscriber key
 * @sqn: SQN = 48-bit sequence number
 * @_rand: RAND = 128-bit random challenge
 * @autn: Buffer for AUTN = 128-bit authentication token
 * @ik: Buffer for IK = 128-bit integrity key (f4), or %NULL
 * @ck: Buffer for CK = 128-bit confidentiality key (f3), or %NULL
 * @res: Buffer for RES = 64-bit signed response (f2), or %NULL
 * @res_len: Max length for res; set to used length or 0 on failure
 */
void xor_generate(const uint8_t *amf, const uint8_t *k,
    const uint8_t *sqn, const uint8_t *_rand, 
    uint8_t *autn, uint8_t *ik, uint8_t *ck, uint8_t *ak,
    uint8_t *res, size_t *res_len) {

  if (ik == NULL || ck == NULL || res == NULL) {
      *res_len = 0;
      return;
  }

  // Temp variables
  uint8_t xdout[16];
  uint8_t cdout[8];

  uint8_t mac[8];

  int i = 0;

  // Use RAND and K to compute RES, CK, IK and AK
  for (i = 0; i < 16; i++) {
    xdout[i] = k[i] ^ _rand[i];
  }

  *res_len = 16;

  for (i = 0; i < 16; i++) {
    res[i]  = xdout[i];
    ck[i]   = xdout[(i + 1) % 16];
    ik[i]   = xdout[(i + 2) % 16];
  }
  for (i = 0; i < 6; i++) {
    ak[i] = xdout[i + 3];
  }

  // Generate cdout
  for (i = 0; i < 6; i++) {
    cdout[i] = sqn[i];
  }
  for (i = 0; i < 2; i++) {
    cdout[6 + i] = amf[i];
  }

  // Generate MAC
  for (i = 0; i < 8; i++) {
    mac[i] = xdout[i] ^ cdout[i];
  }

  // Generate AUTN (autn = sqn ^ ak |+| amf |+| mac)
  for (i = 0; i < 6; i++) {
    autn[i] = sqn[i] ^ ak[i];
  }
  for (i = 0; i < 2; i++) {
    autn[6 + i] = amf[i];
  }
  for (i = 0; i < 8; i++) {
    autn[8 + i] = mac[i];
  }

  return;

}