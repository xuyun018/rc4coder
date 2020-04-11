#ifndef CRYPT_H
#define CRYPT_H
//---------------------------------------------------------------------------
#include <Windows.h>
//---------------------------------------------------------------------------
#define BOX_LEN 256
//---------------------------------------------------------------------------
int WINAPI CryptRC4(const unsigned char *data, int data_len, const unsigned char *key, int key_len, unsigned char *out, int *out_len);
//---------------------------------------------------------------------------
#endif