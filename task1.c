#ifndef __RSA_H_
#define __RSA_H_
#endif
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>


BIGNUM* get_rsa_priv_key(BIGNUM* p, BIGNUM* q, BIGNUM* e);
BIGNUM* rsa_encrypt(BIGNUM* message, BIGNUM* mod, BIGNUM* pub_key);
BIGNUM* rsa_decrypt(BIGNUM* encrypted_message, BIGNUM* priv_key, BIGNUM* pub_key);
void printHX(const char* st);
void printBN(char* msg, BIGNUM * a);
int hex_to_int(char c);
int hex_to_ascii(const char c, const char d);

int main () 
{
	/*
		Task 1 - Deriving a private key
											*/
	
	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *e = BN_new();
	
	// Assign the first large prime
	BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
	
	// Assign the second large prime
	BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
	
	// Assign the Modulus
	BN_hex2bn(&e, "0D88C3");

	BIGNUM* priv_key1 = get_rsa_priv_key(p, q, e);
	printBN("Khoa bi mat cua task1 la: ", priv_key1);



/*Task 2 - Encrypting a message */

	BIGNUM* enc = BN_new();
	BIGNUM* dec = BN_new();
	BIGNUM* enca = BN_new();
	BIGNUM* encb = BN_new();

	BIGNUM* priv_key = BN_new();
	BN_hex2bn(&priv_key, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

	BIGNUM* pub_key = BN_new();
	BN_hex2bn(&pub_key, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	printBN("the public key is: ", pub_key);

	BIGNUM* mod = BN_new();
	BN_hex2bn(&mod, "010001");

	BIGNUM* message = BN_new();
	BN_hex2bn(&message, "4120746f702073656372657421");

	printBN("ma hex cua doan message la: ", message);
	enc = rsa_encrypt(message, mod, pub_key);
	printBN("Ma hoa message cua task2 la: ", enc);
	dec = rsa_decrypt(enc, priv_key, pub_key);
	printf("Giai ma message cua task2 la: ");
	printHX(BN_bn2hex(dec));
	printf("\n");

	/*Task 3 decrypt */
	BIGNUM* task3_enc = BN_new();
	BN_hex2bn(&task3_enc, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
	
	dec = rsa_decrypt(task3_enc, priv_key, pub_key);
	printf("the decrypted message for task3 is: ");
	printHX(BN_bn2hex(dec));
	printf("\n");
	
	/*Task 4 - Signing a message*/
	BIGNUM* BN_task4 = BN_new();
	BN_hex2bn(&BN_task4, "49206f776520796f75202432303030");
	enc = rsa_encrypt(BN_task4, priv_key, pub_key);
	printBN("Chu ky duoc tao o task4 la: ", enc);
// De chac chan la minh da tao chu ky dung thi ta thu decrypt lai thanh message.
	dec = rsa_decrypt(enc, mod, pub_key);
	printf("Thong diep o task 4 la: ");
	printHX(BN_bn2hex(dec));
	printf("\n");
//You owm me $123456789
	BIGNUM* BN_task4a = BN_new();
	BN_hex2bn(&BN_task4a, "596f75206f7765206d652024313233343536373839");
	enca = rsa_encrypt(BN_task4a, priv_key, pub_key);
	printBN("Chu ky duoc tao o You owm me $123456789 la: ", enca);
	printf("\n");
//I own you $3000
	BIGNUM* BN_task4b = BN_new();
	BN_hex2bn(&BN_task4b, "49206f776520796f75202433303030");
	encb = rsa_encrypt(BN_task4b, priv_key, pub_key);
	printBN("Chu ky duoc tao o I owm you $3000 la: ", encb);
	printf("\n");	

/* Task 5 - Verifying a signature */
	BIGNUM* BN_task5 = BN_new();
	BIGNUM* S = BN_new();
	BN_hex2bn(&BN_task5, "4c61756e63682061206d6973736c652e");
	BN_hex2bn(&pub_key, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
	BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");

	dec = rsa_decrypt(S, mod, pub_key);
	printf("Thong diep cua task5 la: ");
	printHX(BN_bn2hex(dec));
	printf("\n");
//Doi 2F thanh 3F.
	BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
	
	dec = rsa_decrypt(S, mod, pub_key);
	printf("Thong diep khi chu ky bi sua doi la: ");

	printHX(BN_bn2hex(dec));
	printf("\n");	

/*Task 6 - Manually Verifying an X.509 Certificate*/
							
	BIGNUM* task6_pub_key = BN_new();
	BN_hex2bn(&task6_pub_key, "A75AC9D50C18210023D5970FEBAEDD5C686B6B8F5060137A81CB97EE8E8A61944B2679F604A72AFBA4DA56BBEEA0A4F07B8A7F551F4793610D6E71513A2524082F8CE1F789D692CFAFB3A73F30EDB5DF21AEFEF54417FDD863D92FD3815A6B5FD347B0ACF2AB3B24794F1FC72EEAB9153A7C184C69B3B52059095E29C363E62E465BAA9490490EB9F0F54AA1092F7C344DD0BC00C506557906CEA2D010F14843E8B95AB59555BD31D21B3D86BEA1EC0D12DB2C9924AD47C26F03E67A70B570CCCD272CA58C8EC2183C92C92E736F0610569340AAA3C552FBE5C505D669685C06B9EE5189E18A0E414D9B92900A89E9166BEFEF75BE7A46B8E3478A1D1C2EA74F");
	printBN("Khoa cong khai cua task6 la: ", task6_pub_key);
	printf("\n");

	BIGNUM* task6_mod = BN_new();
	BN_hex2bn(&task6_mod, "010001");
	

	BIGNUM* BN_task6 = BN_new();
	BN_hex2bn(&BN_task6, "3840ace89dbb0978d9445e9254f65676dd9f0d74a7ab52780cad37acb5a54a1d1f7922796d6ddd99bc91995ffc2740a37a5ea6fa13c2d8720f635b3f88293232a9c75685a0268cf82aaef5d3e0801e291b9c119060b3c25a5b3fc29d50da3468736b715287c23d65accec0a99e4a0cde58600e2dd4c8265b7298966ca60dba4c6ae906d3f48c77656d40cd301a4b485c0a56b41668f94f6c2b77ce02f2d25f0fab171fe332c46f9a3f5c738636757c137e30619abe88090655efba05f047f0f6fc269023f259cb12b7ffbc69639c008643d445fe32b8bf5b1c22eb31d2ce4c91185ac87826de1ee3db822e67f3fa19aa7842338aee0aebb75ae574c1c2445bcf");

	BIGNUM* task6_dec = rsa_decrypt(BN_task6, task6_mod, task6_pub_key);

	printBN("Ma hash cua task6 la: ", task6_dec);
	printf("\n");

	printf("Ma hash da duoc tinh truoc la: ");
	printf("ddb326d3b23ca037021c221954d67891b25a430e406bae5954ea81fa116b888a");
	printf("\n");
}
//Dinh nghia ham  
BIGNUM* get_rsa_priv_key(BIGNUM* p, BIGNUM* q, BIGNUM* e)
{

	BN_CTX *ctx = BN_CTX_new();
	BIGNUM* p_minus_one = BN_new();
	BIGNUM* q_minus_one = BN_new();
	BIGNUM* one = BN_new();
	BIGNUM* tt = BN_new();

	BN_dec2bn(&one, "1");
	BN_sub(p_minus_one, p, one);
	BN_sub(q_minus_one, q, one);
	BN_mul(tt, p_minus_one, q_minus_one, ctx);

	BN_mul(tt,p,q,ctx);

	BIGNUM* res = BN_new();
	BN_mod_inverse(res, e, tt, ctx);
	BN_CTX_free(ctx);
	return res;
}

BIGNUM* rsa_encrypt(BIGNUM* message, BIGNUM* mod, BIGNUM* pub_key)
{
	/*
		compute the RSA cipher on message
		the ciphertext is congruent to: message^mod (modulo pub_key)
	*/
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM* enc = BN_new();
	BN_mod_exp(enc, message, mod, pub_key, ctx);
	BN_CTX_free(ctx);
	return enc;
}

BIGNUM* rsa_decrypt(BIGNUM* enc, BIGNUM* priv_key, BIGNUM* pub_key)
{
	/*
		compute the original message: (message ^ mod) ^ pub_key
	*/
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM* dec = BN_new();
	BN_mod_exp(dec, enc, priv_key, pub_key, ctx);
	BN_CTX_free(ctx);
	return dec;
}
void printHX(const char* st)
{
	int length = strlen(st);
	if (length % 2 != 0) {
		printf("%s\n", "invalid hex length");
		return;
	}
	int i;
	char buf = 0;
	for(i = 0; i < length; i++) {
		if(i % 2 != 0)
			printf("%c", hex_to_ascii(buf, st[i]));
		else
		    buf = st[i];
	}
	printf("\n");

}

void printBN(char* msg, BIGNUM * a)
{
    char * number_str = BN_bn2hex(a);
    printf("%s 0x%s\n", msg, number_str);
    OPENSSL_free(number_str);
}
int hex_to_int(char c)
{
    if (c >= 97)
        c = c - 32;
    int first = c / 16 - 3;
    int second = c % 16;
    int result = first * 10 + second;
    if (result > 9) result--;
    return result;
}

int hex_to_ascii(const char c, const char d)
{
	int high = hex_to_int(c) * 16;
	int low = hex_to_int(d);
	return high+low;
}
