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
	printBN("the private key for task1 is:", priv_key1);

	BIGNUM* enc = BN_new();
	BIGNUM* dec = BN_new();

	/*
		Task 2 - Encrypting a message
										*/
	// Assign the private key
	BIGNUM* priv_key = BN_new();
	BN_hex2bn(&priv_key, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

	// Assign the public key
	BIGNUM* pub_key = BN_new();
	BN_hex2bn(&pub_key, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	printBN("the public key is: ", pub_key);

	// Assign the Modulus
	BIGNUM* mod = BN_new();
	BN_hex2bn(&mod, "010001");

	// We are going to encrypt the message 'A top secret!'.
	// In order to use RSA, first we need to convert this message into hex.
	// Then we can convert the hex into a BIGNUM for the computations.
	BIGNUM* message = BN_new();
	BN_hex2bn(&message, "4120746f702073656372657421");

	printBN("the plaintext message for task2 is: ", message);
	enc = rsa_encrypt(message, mod, pub_key);
	printBN("the encrypted message for task2 is: ", enc);
	dec = rsa_decrypt(enc, priv_key, pub_key);
	printf("the decrypted message for task2 is: ");
	printHX(BN_bn2hex(dec));
	printf("\n");
	
	/*
		Task 3 - Decrypting a message
										*/
	// We are going to decrypt the following ciphertext
	// The ciphertext was given in hexadecimal format.
	// So we must convert to a BIGNUM for the computations.
	BIGNUM* task3_enc = BN_new();
	BN_hex2bn(&task3_enc, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
	
	// We already have the public and private keys. 
	// We can decrypt using our rsa_decrypt function.
	dec = rsa_decrypt(task3_enc, priv_key, pub_key);
	printf("the decrypted message for task3 is: ");
	printHX(BN_bn2hex(dec));
	printf("\n");

	/*
		Task 4 - Signing a message
									*/
	// In this task, we are to generate the signature for a message.
	// The message is "I owe you $2000". First we must convert this to hex.
	// python -c ’print("I owe you $2000".encode("hex"))’
	// Once we have the hex, we convert to a BIGNUM for the computations.
	BIGNUM* BN_task4 = BN_new();
	BN_hex2bn(&BN_task4, "49206f776520796f75203030302e");
	
	// Since we already have the private key, all we need to do is encrypt.
	enc = rsa_encrypt(BN_task4, priv_key, pub_key);
	printBN("the signature for task4 is: ", enc);
	
	// To verify the operations were conducted correctly, we decrypt as well.
	dec = rsa_decrypt(enc, mod, pub_key);
	printf("the message for task4 is: ");
	printHX(BN_bn2hex(dec));
	printf("\n");

	/*
		Task 5 - Verifying a signature
										*/
	// In this task, we are going to verify a signature.
	// So we will use our public key to decrypt a message 
	// that has been encrypted with the private key,
	// And then compare the message with our decrypted result.
	BIGNUM* BN_task5 = BN_new();
	BIGNUM* S = BN_new();
	BN_hex2bn(&BN_task5, "4c61756e63682061206d6973736c652e");
	BN_hex2bn(&pub_key, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
	BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
	
	// Here we decrypt the message with the public key.
	dec = rsa_decrypt(S, mod, pub_key);
	printf("the message for task5 is: ");
	
	printHX(BN_bn2hex(dec));
	printf("\n");
	
	// Now we corrupt the signature, and try to verify again.
	BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
	
	// Here we decrypt a corrupted message with the public key.
	dec = rsa_decrypt(S, mod, pub_key);
	printf("the message for task5 is: ");
	
	// We should see a corrupted output here.
	printHX(BN_bn2hex(dec));
	printf("\n");

	/*
		Task 7 - Manually Verifying an X.509 Certificate
															*/
	
	// Assign the public key
	BIGNUM* task7_pub_key = BN_new();
	BN_hex2bn(&task7_pub_key, "B6E02FC22406C86D045FD7EF0A6406B27D22266516AE42409BCEDC9F9F76073EC330558719B94F940E5A941F5556B4C2022AAFD098EE0B40D7C4D03B72C8149EEF90B111A9AED2C8B8433AD90B0BD5D595F540AFC81DED4D9C5F57B786506899F58ADAD2C7051FA897C9DCA4B182842DC6ADA59CC71982A6850F5E44582A378FFD35F10B0827325AF5BB8B9EA4BD51D027E2DD3B4233A30528C4BB28CC9AAC2B230D78C67BE65E71B74A3E08FB81B71616A19D23124DE5D79208AC75A49CBACD17B21E4435657F532539D11C0A9A631B199274680A37C2C25248CB395AA2B6E15DC1DDA020B821A293266F144A2141C7ED6D9BF2482FF303F5A26892532F5EE3");
	printBN("the public key is: ", task7_pub_key);

	// Assign the modulus
	BIGNUM* task7_mod = BN_new();
	BN_hex2bn(&task7_mod, "010001");
	

	BIGNUM* BN_task7 = BN_new();
	BN_hex2bn(&BN_task7, "84a89a11a7d8bd0b267e52247bb2559dea30895108876fa9ed10ea5b3e0bc72d47044edd4537c7cabc387fb66a1c65426a73742e5a9785d0cc92e22e3889d90d69fa1b9bf0c16232654f3d98dbdad666da2a5656e31133ece0a5154cea7549f45def15f5121ce6f8fc9b04214bcf63e77cfcaadcfa43d0c0bbf289ea916dcb858e6a9fc8f994bf553d4282384d08a4a70ed3654d3361900d3f80bf823e11cb8f3fce7994691bf2da4bc897b811436d6a2532b9b2ea2262860da3727d4fea573c653b2f2773fc7c16fb0d03a40aed01aba423c68d5f8a21154292c034a220858858988919b11e20ed13205c045564ce9db365fdf68f5e99392115e271aa6a8882");


	BIGNUM* task7_dec = rsa_decrypt(BN_task7, task7_mod, task7_pub_key);
	
	printBN("the hash for task7 is: ", task7_dec);
	printf("\n");

	printf("the pre-computed hash was: ");
	printf("902677e610fedcdd34780e359692eb7bd199af35115105636aeb623f9e4dd053");
	printf("\n");

}
//Dinh nghia ham  
BIGNUM* get_rsa_priv_key(BIGNUM* p, BIGNUM* q, BIGNUM* e)
{
	/*
		given two large prime numbers, compute a private key
		using the modulo inverse of the totatives of the product p*q
	*/
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM* p_minus_one = BN_new();
	BIGNUM* q_minus_one = BN_new();
	BIGNUM* one = BN_new();
	BIGNUM* tt = BN_new();

	BN_dec2bn(&one, "1");
	BN_sub(p_minus_one, p, one);
	BN_sub(q_minus_one, q, one);
	BN_mul(tt, p_minus_one, q_minus_one, ctx);

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
