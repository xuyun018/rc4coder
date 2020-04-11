#include "cryptrc4.h"
//---------------------------------------------------------------------------
int GetKey(const unsigned char *pass, int pass_len, unsigned char *out)
{
	int i, j;
	unsigned char a;

	for(i = 0; i < BOX_LEN; i++)
		out[i] = i;

	j = 0;
	for(i = 0; i < BOX_LEN; i++)
	{
		j = (pass[i % pass_len] + out[i] + j) % BOX_LEN;
		a = out[i];
		out[i] = out[j];
		out[j] = a;
	}
	return -1;
}

int WINAPI CryptRC4(const unsigned char *data, int data_len, const unsigned char *key, int key_len, unsigned char *out, int *out_len)
{
	unsigned char box[BOX_LEN];
	unsigned char a;
	int x = 0;
	int y = 0;
	int k;

	GetKey(key, key_len, box);

	for (k = 0; k < data_len; k++)
	{
		x = (x + 1) % BOX_LEN;
		y = (box[x] + y) % BOX_LEN;
		a = box[x];
		box[x] = box[y];
		box[y] = a;
		out[k] = data[k] ^ box[(box[x] + box[y]) % BOX_LEN];
	}

	*out_len = data_len;
	return -1;
}
//---------------------------------------------------------------------------