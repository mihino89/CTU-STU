#include <stdio.h>
#include <stdint.h>
#include <time.h>

/* AES-128 simple implementation template and testing */

/*
Author: YOUR_NAME_HERE, username@fit.cvut.cz
Template: Jiri Bucek 2017
AES specification:
http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
*/

/* AES Constants */
// The other matrix - Galois fields

const int G_FIELD_o[4][4] = {
	{2, 3, 1, 1},
	{1, 2, 3, 1},
	{1, 1, 2, 3},
	{3, 1, 1, 2}
};

uint32_t TB0[256] = { 0 };
uint32_t TB1[256] = { 0 };
uint32_t TB2[256] = { 0 };
uint32_t TB3[256] = { 0 };

// forward sbox
const uint8_t SBOX_o[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
}; 

const uint8_t rCon_o[12] = {
	0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
};

/* AES state type */
typedef uint32_t t_state[4];

/* Helper functions */
void hexprint16_o(uint8_t *p) {
	for (int i = 0; i < 16; i++)
		printf("%02hhx ", p[i]);
	puts("");
}

void hexprintw_o(uint32_t w) {
	for (int i = 0; i < 32; i += 8)
		printf("%02hhx ", (w >> i) & 0xffU);
}

void hexprintw_os(uint32_t * p, int cnt) {
	for (int i = 0; i < cnt; i++)
		hexprintw_o(p[i]);
	puts("");
}
void printstate_o(t_state s) {
	hexprintw_o(s[0]);
	hexprintw_o(s[1]);
	hexprintw_o(s[2]);
	hexprintw_o(s[3]);
	puts("");
}

uint32_t word_o(uint8_t a0, uint8_t a1, uint8_t a2, uint8_t a3) {
	return a0 | (uint32_t)a1 << 8 | (uint32_t)a2 << 16 | (uint32_t)a3 << 24;
}

uint8_t wbyte_o(uint32_t w, int pos) {
	return (w >> (pos * 8)) & 0xff;
}

// **************** AES  functions ****************
uint32_t subWord_s(uint32_t w) {
	return word_o(SBOX_o[wbyte_o(w, 0)], SBOX_o[wbyte_o(w, 1)], SBOX_o[wbyte_o(w, 2)], SBOX_o[wbyte_o(w, 3)]);
}


// { 0x01234567, 0x89abcdef, 0xdeadbeef, 0x00112233 }
void subBytes_o(t_state state) {
	
    for (int i = 0; i < 4; i++){
        state[i] = subWord_s(state[i]);
    }
}


void shiftRows_o(t_state state) {

    unsigned char tmp[16], tmp1[16];

    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            tmp[j*4+i] = wbyte_o(state[i],j);
        }
    }    
    /** Trying this
     * 67 ef ef 33 
     * 45 cd be 22 
     * 23 ab ad 11 
     * 01 89 de 00
    */

    tmp1[0] = tmp[0];
    tmp1[1] = tmp[1];
    tmp1[2] = tmp[2];
    tmp1[3] = tmp[3];

    tmp1[4] = tmp[5];
    tmp1[5] = tmp[6];
    tmp1[6] = tmp[7];
    tmp1[7] = tmp[4];

    tmp1[8] = tmp[10];
    tmp1[9] = tmp[11];
    tmp1[10] = tmp[8];
    tmp1[11] = tmp[9];

    tmp1[12] = tmp[15];
    tmp1[13] = tmp[12];
    tmp1[14] = tmp[13];
    tmp1[15] = tmp[14];

    /**
     * 67 ef ef 33 
     * cd be 22 45 
     * ad 11 23 ab 
     * 00 01 89 de
    */

    for (int i = 0; i < 4; i ++){
        state[i] = word_o(tmp1[0+i], tmp1[4+i], tmp1[8+i], tmp1[12+i]);
    }
}

uint8_t xtime_o(uint8_t a) {
	return ((a << 1) ^ (((a >> 7) & 1) * 0x1b));
}

// not mandatory - mix a single column
uint32_t mixColumn_o(uint32_t c) {
	return 0; /* ??? */
}


void mixColumns_o(t_state s) {
	uint8_t state[4][4];
    for(int i = 0 ; i < 4 ; i++){
        for(int j = 0 ; j < 4 ; j++){
            state[i][j] = wbyte_o(s[i],j);
        }
    }
    
    uint8_t newState[4][4];
    for(int x = 0; x < 4; x++){
        for(int y = 0; y < 4; y++){
            uint8_t sum = 0;
            for(int z = 0; z < 4; z++){
                if(G_FIELD_o[x][z] == 1)
                    sum ^= state[y][z];
                else if(G_FIELD_o[x][z] == 2)
                    sum ^= xtime_o(state[y][z]);
                else 
                    sum ^= (xtime_o(state[y][z])^state[y][z]);
            }
            newState[x][y] = sum;
        }
    }
    
    for (int i = 0; i < 4; i++) {
        s[i] = word_o(newState[0][i],newState[1][i],newState[2][i],newState[3][i]);
    }
}


// Rotation left
uint32_t rotationLeft_o(uint32_t word_o) {
	uint32_t tmp = wbyte_o(word_o,0);
    return (word_o >> 8) | ((tmp & 0xFF) << 24);
}

/*
* Key expansion from 128bits (4*32b)
* to 11 round keys (11*4*32b)
* each round key is 4*32b
*/
void expandKey_o(uint8_t k[16], uint32_t ek[44]) {
    int counter = 0;

	while(counter < 4){
		ek[counter] = word_o(k[4*counter], k[4*counter+1], k[4*counter+2], k[4*counter+3]);
		counter++;
	}
 
    int bG = 4;
	uint32_t tmp;
 
    while(bG < 44) {
        tmp = ek[bG-1];
        if(bG % 4 == 0) {
			// Sbox + rotation L + rCon_o
            tmp = subWord_s(rotationLeft_o(ek[bG-1])) ^ rCon_o[bG/4];
		}
        ek[bG] = ek[bG-4] ^ tmp;
        bG++;
	}
}

uint8_t mul_o(uint8_t bFac1, uint8_t bFac2) {
	uint8_t p = 0;
	uint8_t counter;
	uint8_t hi_bit_set;
	for(counter = 0; counter < 8; counter++) {
		if((bFac2 & 1) == 1) 
			p ^= bFac1;
		hi_bit_set = (bFac1 & 0x80);
		bFac1 <<= 1;
		if(hi_bit_set == 0x80) 
			bFac1 ^= 0x1b;		
		bFac2 >>= 1;
	}
	return p;
}


void init_tboxes_o(){
    for(int i = 0; i < 256; i++){
        TB0[i] = word_o( mul_o(SBOX_o[i], 02), SBOX_o[i], SBOX_o[i], mul_o(SBOX_o[i], 03));      
        TB1[i] = word_o( mul_o(SBOX_o[i], 03), mul_o(SBOX_o[i], 02), SBOX_o[i], SBOX_o[i]);
        TB2[i] = word_o(SBOX_o[i], mul_o(SBOX_o[i], 03), mul_o(SBOX_o[i], 02), SBOX_o[i]);
        TB3[i] = word_o(SBOX_o[i], SBOX_o[i], mul_o(SBOX_o[i], 03), mul_o(SBOX_o[i], 02));
    }
}


void TBox_o(t_state state){

    /**
     * ab dc cd 32
     * 67 10 01 fe
     * 23 54 45 ba
     * ef 98 89 76
    */

    t_state tmp;
    for(int i = 0; i < 4; i++)
       tmp[i] = TB0[wbyte_o(state[i], 0)] ^ TB1[wbyte_o(state[(i+1)%4], 1)] ^ TB2[wbyte_o(state[(i+2)%4], 2)] ^ TB3[wbyte_o(state[(i+3)%4], 3)];
   
    for(int i = 0; i < 4; i++)
        state[i] = tmp[i];
}


/** 
 * Adding expanded round key (prepared before) 
 * XOR operation  
 * Neotestovane !
*/
void addRoundKey_o(t_state state, uint32_t ek[], short round) {	
    for (int i = 0; i < 4; i++)
        state[i] ^= ek[4*round+i];
}

void aes_o(uint8_t *in, uint8_t *out, uint8_t *skey) {
    uint8_t help=8;
    // printf("0x%08x", xtime_o(help));
    // printf("0x%08x", mul_o(help, 02));

	//... Initialize ...
	unsigned short round = 0;
    const int numberOfRounds = 10;

	t_state state;

	state[0] = word_o(in[0],  in[1],  in[2],  in[3]);
	state[1] = word_o(in[4], in[5], in[6], in[7]);
    state[2] = word_o(in[8], in[9], in[10], in[11]);
    state[3] = word_o(in[12], in[13], in[14], in[15]);

	// printf("IN:  "); printstate_o(state);

	uint32_t expKey[11 * 4];

	expandKey_o(skey, expKey);

	// for (int i = 0; i < 11; i++) {
	// 	// printf("K%02d: ", i);
	// 	hexprintw_os(expKey + 4 * i, 4);
	// }

	addRoundKey_o(state, expKey, 0);
	// printf("ARK: "); printstate_o(state);

	for(int i = 1; i < numberOfRounds; i++){
        TBox_o(state);
        // printstate_o(state);
        addRoundKey_o(state, expKey, i);
    }

    // Final round
    subBytes_o(state);
    shiftRows_o(state);
    addRoundKey_o(state, expKey, numberOfRounds);

	for (int i = 0; i < 16; i++) {
		if (i < 4) out[i] = wbyte_o(state[0], i % 4);
		else if (i < 8) out[i] = wbyte_o(state[1], i % 4);
		else if (i < 12) out[i] = wbyte_o(state[2], i % 4);
		else out[i] = wbyte_o(state[3], i % 4);
	}
}

//****************************
// MAIN function: AES testing
//****************************
int aes_optimazed(){
	int test_failed = 0;
    // init_tboxes_o();
	// test subBytes_o
	printf("Testing subBytes_o\n");
	{
		t_state state = { 0x01234567, 0x89abcdef, 0xdeadbeef, 0x00112233 };
		t_state res_state = { 0x7c266e85, 0xa762bddf, 0x1d95aedf, 0x638293c3 };
		subBytes_o(state);
		printf("0x%08x, 0x%08x, 0x%08x, 0x%08x\n", state[0], state[1], state[2], state[3]);
		for (int i = 0; i < 4; i++) {
			if (state[i] != res_state[i]) { printf("Mismatch at state[%d]!\n", i); test_failed = 1; }
		}
	}
	// test shiftRows_o
	printf("Testing shiftRows_o\n");
	{
		t_state state = { 0x01234567, 0x89abcdef, 0xdeadbeef, 0x00112233 };
		t_state res_state = { 0x00adcd67, 0x0111beef, 0x892322ef, 0xdeab4533 };
		shiftRows_o(state);
		printf("0x%08x, 0x%08x, 0x%08x, 0x%08x\n", state[0], state[1], state[2], state[3]);
		for (int i = 0; i < 4; i++) {
			if (state[i] != res_state[i]) { printf("Mismatch at state[%d]!\n", i); test_failed = 1; }
		}
	}
	// test mixColumns_o
	printf("Testing mixColumns_o\n");
	{
		t_state state = { 0x01234567, 0x89abcdef, 0xdeadbeef, 0x00112233 };
		t_state res_state = { 0xcd678923, 0x45ef01ab, 0x9e69ba6f, 0x66334411 };
		mixColumns_o(state);
		printf("0x%08x, 0x%08x, 0x%08x, 0x%08x\n", state[0], state[1], state[2], state[3]);
		for (int i = 0; i < 4; i++) {
			if (state[i] != res_state[i]) { printf("Mismatch at state[%d]!\n", i); test_failed = 1; }
		}
	}
	// test xtime_o
	printf("Testing xtime_o\n");
	{
		uint8_t res[256] = { 0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12,
			0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e, 0x20, 0x22, 0x24, 0x26,
			0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a,
			0x3c, 0x3e, 0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e,
			0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e, 0x60, 0x62,
			0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76,
			0x78, 0x7a, 0x7c, 0x7e, 0x80, 0x82, 0x84, 0x86, 0x88, 0x8a,
			0x8c, 0x8e, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e,
			0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2,
			0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe, 0xc0, 0xc2, 0xc4, 0xc6,
			0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda,
			0xdc, 0xde, 0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee,
			0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe, 0x1b, 0x19,
			0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15, 0x0b, 0x09, 0x0f, 0x0d,
			0x03, 0x01, 0x07, 0x05, 0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31,
			0x37, 0x35, 0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25,
			0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55, 0x4b, 0x49,
			0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45, 0x7b, 0x79, 0x7f, 0x7d,
			0x73, 0x71, 0x77, 0x75, 0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61,
			0x67, 0x65, 0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95,
			0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81, 0x87, 0x85, 0xbb, 0xb9,
			0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5, 0xab, 0xa9, 0xaf, 0xad,
			0xa3, 0xa1, 0xa7, 0xa5, 0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1,
			0xd7, 0xd5, 0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5,
			0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 0xeb, 0xe9,
			0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5 };
		for (uint16_t i = 0; i < 256; i++) {
			// printf("0x%02hhx,   ", xtime_o((uint8_t)i));
			if (xtime_o((uint8_t)i)!=res[i]) { 
				printf("\nMismatch at xtime_o(0x%02x)! Comparison interrupted.\n", i);  test_failed = 1;
				break;
			}
		}
		puts("");
	}

	// test key expansion
	printf("Testing expandKey_o\n");
	{
		uint8_t key_b[16] = { 0xef, 0xbe, 0xad, 0xde, 0xbe, 0xba, 0xfe, 0xca, 0x0D, 0xF0, 0xAD, 0xBA, 0x00, 0x11, 0x22, 0x33 };
		uint32_t key_w[44] = {  0 /*, ...*/ };
		uint32_t res_key_w[44] = { 
			0xdeadbeef, 0xcafebabe, 0xbaadf00d, 0x33221100,
			0xbd6e2d6c, 0x779097d2, 0xcd3d67df, 0xfe1f76df,
			0x23d5ed56, 0x54457a84, 0x99781d5b, 0x67676b84,
			0x7c50682d, 0x281512a9, 0xb16d0ff2, 0xd60a6476,
			0x44a60f66, 0x6cb31dcf, 0xddde123d, 0x0bd4764b,
			0xf78d474e, 0x9b3e5a81, 0x46e048bc, 0x4d343ef7,
			0x9f6e5fdc, 0x0450055d, 0x42b04de1, 0x0f847316,
			0xd8180013, 0xdc48054e, 0x9ef848af, 0x917c3bb9,
			0x8e991071, 0x52d1153f, 0xcc295d90, 0x5d556629,
			0x2bd5ec59, 0x7904f966, 0xb52da4f6, 0xe878c2df,
			0xb54e504a, 0xcc4aa92c, 0x79670dda, 0x911fcf05, 
		};
		expandKey_o(key_b, key_w);
		for (int i = 0; i < 44; i++) {
			printf("0x%08x, ", key_w[i]);
			if (i % 4 == 3) printf("\n");
		}

		for (int i = 0; i < 44; i++) {
			if (key_w[i] != res_key_w[i]) { 
				printf("Mismatch at key_w[%d]! Comparison interrupted.\n", i);  test_failed = 1;
				break;
			}
		}
		printf("Testing addRoundKey_o\n");
		// test  AddRoundKey (last round)
		t_state state = { 0x01234567, 0x89abcdef, 0xdeadbeef, 0x00112233 };
		t_state res_state = { 0xb46d152d, 0x45e164c3, 0xa7cab335, 0x910eed36 };
		addRoundKey_o(state, key_w, 10);
		printf("0x%08x, 0x%08x, 0x%08x, 0x%08x\n", state[0], state[1], state[2], state[3]);
		for (int i = 0; i < 4; i++) {
			if (state[i] != res_state[i]) { printf("Mismatch at state[%d]!\n", i); }
		}

	}


    clock_t tStart = clock();
	// test aes_o encryption
	printf("Testing aes_o\n");
	{
		uint8_t key[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
		uint8_t in[16] =  { 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89};
		uint8_t out[16] = { 0, /*...*/ };
		uint8_t res_out[16] = { 0xa3, 0x3a, 0xca, 0x68, 0x72, 0xa2, 0x27, 0x74, 0xbf, 0x99, 0xf3, 0x71, 0xaa, 0x99, 0xd2, 0x5a };

		printf("Key: ");
		hexprint16_o(key);
		puts("");
		printf("In:  ");
		hexprint16_o(in);
		puts("");

		aes_o(in, out, key);

		printf("Out: ");
		hexprint16_o(out);
		puts("");

		for (int i = 0; i < 16; i++) {
			if (out[i] != res_out[i]) { printf("Mismatch at out[%d]!\n", i); test_failed = 1; }
		}
	}
	if (test_failed) {
		printf("|*********** SOME TEST(S) FAILED ***********|\n");
		printf("Please fix me!\n");
	}
	else {
		printf("============== All tests OK! ===============\n");
	}
    printf("Time taken: %.10fs\n", ((double)(clock() - tStart)/CLOCKS_PER_SEC)*1000);
	return  test_failed;
}
