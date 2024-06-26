/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2007 Nokia Corporation. All rights reserved.
 *  Contact: Rémi Denis-Courmont
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Nice GLib ICE library.
 *
 * The Initial Developers of the Original Code are Collabora Ltd and Nokia
 * Corporation. All Rights Reserved.
 *
 * Contributors:
 *   Rémi Denis-Courmont, Nokia
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * the GNU Lesser General Public License Version 2.1 (the "LGPL"), in which
 * case the provisions of LGPL are applicable instead of those above. If you
 * wish to allow use of your version of this file only under the terms of the
 * LGPL and not to allow others to use your version of this file under the
 * MPL, indicate your decision by deleting the provisions above and replace
 * them with the notice and other provisions required by the LGPL. If you do
 * not delete the provisions above, a recipient may use your version of this
 * file under either the MPL or the LGPL.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif


#include "sha1.h"
#include "md5.h"
#include "stuncrc32.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include <string>

void print_bytes (uint8_t *bytes, int len)
{
  int i;

  printf ("0x");
  for (i = 0; i < len; i++)
    printf ("%02x", bytes[i]);
  printf ("\n");
}

void test_sha1 (uint8_t *str, uint8_t *expected) {
  SHA1_CTX ctx;
  uint8_t sha1[20];

  SHA1Init(&ctx);
  SHA1Update(&ctx, str, strlen ((const char*)str));
  SHA1Final(sha1, &ctx);

  printf ("SHA1 of '%s' : ", str);
  print_bytes (sha1, SHA1_MAC_LEN);
  printf ("Expected : ");
  print_bytes (expected, SHA1_MAC_LEN);

  if (memcmp (sha1, expected, SHA1_MAC_LEN))
    exit (1);

}

void mtest_hmac (uint8_t *key, uint8_t *str1, int len_str1) {
  uint8_t hmac[20];

  printf("%4d", len_str1);	
  printf ("\n");

  hmac_sha1(key, strlen((const char*)key), str1, len_str1, hmac); 
  printf ("HMAC of '%s' with key '%s' is : ", str1, key);
  print_bytes (hmac, SHA1_MAC_LEN);

}

void test_hmac (uint8_t *key, uint8_t *str, uint8_t *expected) {
  uint8_t hmac[20];
  hmac_sha1(key, strlen ((const char*)key), str, strlen((const char*)str), hmac); 
  printf ("HMAC of '%s' with key '%s' is : ", str, key);
  print_bytes (hmac, SHA1_MAC_LEN);
  printf ("Expected test_hmac: ");
  print_bytes (expected, SHA1_MAC_LEN);

  if (memcmp (hmac, expected, SHA1_MAC_LEN))
    exit (1);
}

void test_md5 (uint8_t *str, uint8_t *expected) {
  MD5_CTX ctx;
  uint8_t md5[20];
  int i;

  MD5Init(&ctx);
  MD5Update(&ctx, str, strlen ((const char*)str));
  MD5Final(md5, &ctx);

  printf ("MD5 of '%s' : 0x", str);
  print_bytes (md5, MD5_MAC_LEN);
  printf ("Expected : ");
  print_bytes (expected, MD5_MAC_LEN);

  if (memcmp (md5, expected, MD5_MAC_LEN))
    exit (1);
}

  uint32_t stun_fingerprint (uint8_t *msg, size_t len)
	{
	  //uint16_t fakelen = htons(len - 20u);
	  return mstun_crc32(msg, len);
	}


int main (void)
{
  //main test
  uint8_t mhmac_key[] = {};
  uint8_t mhmac_str[] = {	
    0x00, 0x01, 0x00, 0x44,  //(4C)
	0x21, 0x12, 0xa4, 0x42,
	0x41, 0x75, 0x6f, 0x4b,
	0x42, 0x56, 0x31, 0x74,
	0x39, 0x48, 0x62, 0x4c,
	0x00, 0x06, 0x00, 0x09,
	0x77, 0x69, 0x45, 0x61,
	0x3a, 0x34, 0x58, 0x4d,
	0x65, 0x00, 0x00, 0x00,
	0xc0, 0x57, 0x00, 0x04,
	0x00, 0x01, 0x00, 0x0a,
	0x80, 0x2a, 0x00, 0x08,
	0xf3, 0x6e, 0x9b, 0x35,
	0xa7, 0xd5, 0x3e, 0x8a,
	0x00, 0x24, 0x00, 0x04,
	0x6e, 0x7f, 0x1e, 0xff,
	//0x00, 0x08, 0x00, 0x14
  };   
  size_t s_mhmac_str = sizeof(mhmac_str);


  uint8_t crc32_str1[] = {	
    0x00, 0x01, 0x00, 0x4c,  //(4c)
	0x21, 0x12, 0xa4, 0x42,
	0x41, 0x75, 0x6f, 0x4b,
	0x42, 0x56, 0x31, 0x74,
	0x39, 0x48, 0x62, 0x4c,
	0x00, 0x06, 0x00, 0x09,
	0x77, 0x69, 0x45, 0x61,
	0x3a, 0x34, 0x58, 0x4d,
	0x65, 0x00, 0x00, 0x00,
	0xc0, 0x57, 0x00, 0x04,
	0x00, 0x01, 0x00, 0x0a,
	0x80, 0x2a, 0x00, 0x08,
	0xf3, 0x6e, 0x9b, 0x35,
	0xa7, 0xd5, 0x3e, 0x8a,
	0x00, 0x24, 0x00, 0x04,
	0x6e, 0x7f, 0x1e, 0xff,
	0x00, 0x08, 0x00, 0x14,
	0xf6, 0x01, 0xce, 0x46,
	0x27, 0x14, 0xc1, 0x07,
	0x95, 0x73, 0xc0, 0xfa,
	0x46, 0x7b, 0xdf, 0x5d,
	0x15, 0xfd, 0x04, 0x45
	//0x80, 0x28, 0x00, 0x04,
	//0xca, 0x2e, 0x49, 0xf4	
  };
  size_t s_crc32_str1 = sizeof(crc32_str1);
  
  
  uint8_t hello_world_hmac[] = {0x8a, 0x3a, 0x84, 0xbc, 0xd0,
                                0xd0, 0x06, 0x5e, 0x97, 0xf1,
                                0x75, 0xd3, 0x70, 0x44, 0x7c,
                                0x7d, 0x02, 0xe0, 0x09, 0x73};
  uint8_t abc_sha1[] = {0xa9, 0x99, 0x3e, 0x36, 0x47,
                        0x06, 0x81, 0x6a, 0xba, 0x3e,
                        0x25, 0x71, 0x78, 0x50, 0xc2,
                        0x6c, 0x9c, 0xd0, 0xd8, 0x9d};
  uint8_t abcd_etc_sha1[] = {0x84, 0x98, 0x3e, 0x44, 0x1c,
                             0x3b, 0xd2, 0x6e, 0xba, 0xae,
                             0x4a, 0xa1, 0xf9, 0x51, 0x29,
                             0xe5, 0xe5, 0x46, 0x70, 0xf1};
  uint8_t abc_md5[] = {0x90, 0x01, 0x50, 0x98,
                       0x3c, 0xd2, 0x4f, 0xb0,
                       0xd6, 0x96, 0x3f, 0x7d,
                       0x28, 0xe1, 0x7f, 0x72};
  uint8_t abcd_etc_md5[] = {0x82, 0x15, 0xef, 0x07,
                            0x96, 0xa2, 0x0b, 0xca,
                            0xaa, 0xe1, 0x16, 0xd3,
                            0x87, 0x6c, 0x66, 0x4a};

  //main test 
  //a=ice-pwd:3WAbvRGJMebJfVsT4R6h48aw
  //a=ice-pwd:jgoxbuIQrpGNC2nzb5E9Lu0V	
 
  mtest_hmac ((uint8_t*)"3WAbvRGJMebJfVsT4R6h48aw", mhmac_str, s_mhmac_str);
  mtest_hmac ((uint8_t*)"jgoxbuIQrpGNC2nzb5E9Lu0V", mhmac_str, s_mhmac_str);

  /* Checks FINGERPRINT */
  uint32_t a = stun_fingerprint(crc32_str1, s_crc32_str1); 
  printf("%08x \n", a ^ 0x5354554e);

  //----------------------------------
  uint32_t table[256];
  generate_table(table);
  
  int32_t crc = update(table, 0, crc32_str1, s_crc32_str1);   
  printf("%08x \n", (crc ^ 0x5354554e));
  //-----------------------------------
  
  //80 28 00 04
  //ca 2e 49 f4 
 
   //Test ok!!!!
   std::string tstr = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
   crc = update(table, 0, tstr.data(), tstr.size());
   printf("%08x \n", crc); 
   //EXPECT 0x171A3F5FU	

/*	
	uint32_t * b = &table[0];
	int j=0;
	int udp_len=24;
	printf("\n%p   ",b);
	for (int i=0; i<udp_len; i++)    
	{
	  printf("%08x ",*(b++));
	  //if (++j==4&&i<4) {      
	  if (++j==4) {      
		  printf("\n");
		  j=0;
		  printf("%p   ",b);    
		};
	};
	//printf("...\n\n");	
*/

  /*
  test_hmac ((uint8_t*)"hello", (uint8_t*)"world", hello_world_hmac);
  //test_hmac ((uint8_t*)"hello", (uint8_t*)"world1", hello_world_hmac);


  test_sha1 ((uint8_t*)"abc", abc_sha1);
  test_md5 ((uint8_t*)"abc", abc_md5);

  test_sha1 ((uint8_t*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      abcd_etc_sha1);
  test_md5 ((uint8_t*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      abcd_etc_md5);

  */	
  return 0;
}
