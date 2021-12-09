#include <stdio.h>
#include <iostream>
#include <cstring>
#include <time.h>
#include <mpir.h>
#include <mpirxx.h>
#include <string>
#include <openssl/sha.h>

using namespace std;

#define PRIME_LENGTH 1024

//Initialise a seed for prime number generation
static unsigned long seed = 353;

//Public Key p, g, y
typedef struct
{
	mpz_t p;
	mpz_t q;
	mpz_t g;
	mpz_t y;

} PublicKey;

//Private Key x
typedef struct
{
	mpz_t x;

} PrivateKey;

typedef struct 
{
	mpz_t r, s;

} Signature;

void randomStateInit(gmp_randstate_t state)
{
	gmp_randinit_mt(state);
	gmp_randseed_ui(state, seed);
}

void generatePrimes(mpz_t prime, gmp_randstate_t state)
{
	//Generate a random number
	mpz_rrandomb(prime, state, PRIME_LENGTH);

  //Check if the number is Prime or not using Miller Rabin Test 
	while (!(mpz_millerrabin(prime, 512)))
	{
		gmp_randclear(state);
		seed++;
		randomStateInit(state);
		mpz_rrandomb(prime, state, PRIME_LENGTH);
	}
	gmp_randclear(state);
	seed++;
}

// Function to generate h, a number between 1 and q-1
void getGenerator(mpz_t h, gmp_randstate_t state, mpz_t q)
{
	mpz_t r, m;
	mpz_inits(r,m, NULL);
    do	
	{
		gmp_randclear(state);
		seed++;
		randomStateInit(state);
		mpz_urandomm(h, state, q);
	    mpz_gcd(r, h, q);
    }while((h == 0) || (mpz_cmp_ui(r,1) != 0));
    mpz_clears(r, m, NULL);
}

// Function to generate a q which divides (p-1)
void generateQ(mpz_t q, mpz_t p , gmp_randstate_t state)
{
	mpz_t n, r;
	mpz_inits(n, r, NULL);
	mpz_set_ui(n, 160);
	mpz_sub_ui(p, p, 1);
	do
	{
		gmp_randclear(state);
		seed++;
		randomStateInit(state);
		mpz_urandomb(q, state, n);
		mpz_mod(r, p, q);	
	}while(!(mpz_cmp_ui(r, 0)));
	mpz_clears(r, n, NULL);
}


//Generate a prime number p and call function to generate g
void generatePublicKey(PublicKey* pubkey, gmp_randstate_t state)
{

    mpz_t d, p;
    mpz_inits(d, p, NULL);
	//Generate p
	randomStateInit(state);
	generatePrimes(pubkey->p, state);

	//Generate q
	randomStateInit(state);
	generateQ(pubkey->q, pubkey->p, state);

	//Generate g
	randomStateInit(state);
	getGenerator(pubkey->g, state, pubkey->q);
	mpz_sub_ui(p, pubkey->p, 1);
	mpz_div(d, p, q);
	mpz_powm(pubkey->g, pubkey->g, d, pubkey->p);
}

//Generate value of x
void generatePrivateKey(PrivateKey*privkey, PublicKey* pubkey, gmp_randstate_t state)
{

	gmp_randclear(state);
	seed++;
	randomStateInit(state);
	mpz_urandomm(privkey->x, state, pubkey->q);
}

//Function to generate the public key and private key
void keyGeneration(PrivateKey*privKey, PublicKey* pubKey, gmp_randstate_t state)
{
	// Function to generate p, q, g
	generatePublicKey(pubKey, state);

	// Function to generate a random x to keep as secret key
	generatePrivateKey(privKey, pubKey, state);

  // Calculate value of y from g, x and p
  // y = (g^x) mod p
	mpz_powm(pubKey->y, pubKey->g, privKey->x, pubKey->p);
}

//Convert char_arr to Int from a string of length 'len'
void decodeText(mpz_t decode,  unsigned char decode_array[], int len)
{
	mpz_import(decode, len, 1, sizeof(decode_array[0]), 0, 0, decode_array);
}

//Convert Int to char_arr
void encodeText(mpz_t encode, unsigned char encode_array[])
{
	mpz_export(encode_array, NULL, 1, sizeof(encode_array[0]), 0, 0, encode);
}

void signingAlgoritm(Signature* sign,string input_msg,PublicKey* pubKey, PrivateKey* privKey, mpz_t k)
{
	mpz_t text, sum, k_inv;
	mpz_inits(text, sum, k_inv,  NULL);

	unsigned char hash[160] = { 0 };
	unsigned char input_array[input_msg.length()] = { 0 };
	copy(input_msg.begin(), input_msg.end(), input_array);

	mpz_powm(sign->r, pubKey->g, k, pubKey->q);
	SHA1(input_array, input_msg.length(), hash);

	decodeText(text, hash, 160);
	gmp_printf("Hashed Value :\n%Zd\n\n", text);

	mpz_mul(sum, privKey->x, sign->r);
	mpz_add(sum, sum, text);
	mpz_mod(sum, sum, pubKey->q);
	mpz_invert(k_inv, k, pubKey->q);
	mpz_mul(sum, sum, k_inv);
	mpz_mod(sum, sum, pubKey->q);
	mpz_set(sign->s, sum);
}

void signatureVerification(string input,Signature sign_ver,PublicKey pubKey)
{
	mpz_t s_inv, w, u1, u2, prod, v, hash_text;
	mpz_inits(s_inv, w, u1, u2, prod, v, hash_text, NULL);
	mpz_invert(s_inv, sign_ver.s, pubKey.q);
	mpz_mod(w, s_inv, pubKey.q);

	unsigned char hash[160] = { 0 };
	unsigned char input_array[input.length()] = { 0 };
	copy(input.begin(), input.end(), input_array);
	SHA1(input_array, input.length(), hash);

	decodeText(hash_text, hash, 160);
	gmp_printf("Hashed Value :\n%Zd\n\n", hash_text);

	mpz_mul(u1, hash_text, w);
	mpz_mod(u1, u1, pubKey.q);
	mpz_mul(u2, sign_ver.r, w);
	mpz_mod(u2, u2, pubKey.q);

	mpz_powm(v, pubKey.g, u1, pubKey.p);
	mpz_powm(prod, pubKey.y, u2, pubKey.p);
	mpz_mul(v, v, prod);
	mpz_mod(v, v, pubKey.p);
	mpz_mod(v, v, pubKey.q);

	if(mpz_cmp(v, sign_ver.r))
	{
		cout<<"\nThe signature are not matching....Rejected";
		gmp_printf("r :\n%Zd\n\n", sign_ver.r);
    gmp_printf("v :\n%Zd\n\n", v);

	}
	else
	{
		cout<<"\nThe signature are matching....Verified";
		gmp_printf("r :\n%Zd\n\n", sign_ver.r);
    gmp_printf("v :\n%Zd\n\n", v);
	}

}


int main()
{	
    PrivateKey privKey; 
    PublicKey pubKey;
    Signature sign, sign_ver;
    mpz_t k;
    mpz_inits(pubKey.g, pubKey.p, pubKey.y, pubKey.q, privKey.x, NULL);
    mpz_inits(sign.r, sign.s, k, NULL);
    int exit = 0;
    gmp_randstate_t state;
    string msg, test;
    unsigned long int len;

    cout<<"\n..........DIGITAL SIGNATURE STANDARD..........";
    keyGeneration(&privKey, &pubKey, state);
    cout<<"\nPublic Key : \n";
    gmp_printf("p :\n%Zd\n\n", pubKey.p);
    gmp_printf("q :\n%Zd\n\n", pubKey.q);
    gmp_printf("g :\n%Zd\n\n", pubKey.g);
    gmp_printf("y :\n%Zd\n\n", pubKey.y);

    while(exit != 1)
    {
        cout<<"Enter message to sign :\n";
        cin>>test;
        len = test.length();

        cout<<"\nGenerating a random value k : ";
        gmp_randclear(state);
        seed++;
        randomStateInit(state);
        mpz_urandomm(k, state, pubKey.q);
        gmp_printf("\n%Zd\n\n", k);

        cout<<"\nPrivate Key\n";
        gmp_printf("x :\n%Zd\n\n", privKey.x);

        signingAlgoritm(&sign, test, &pubKey, &privKey, k);
        cout<<"\nSignature\n";
        gmp_printf("r :\n%Zd\n\n", sign.r);
        gmp_printf("s :\n%Zd\n\n", sign.s);

        cout<<"\nVerification : ";
        cout<<"\nEnter the values of Signature for verification :\n";
        cout<<"r : ";
        cin>>sign_ver.r;
        cout<<"\ns : ";
        cin>>sign_ver.s;

        signatureVerification(test, sign_ver, pubKey);

        cout<<"\n\nExit (Yes : 1 | No : 0)\n";
        cin>>exit;
    }

    mpz_clears(k, NULL);
	  return 0;
}

