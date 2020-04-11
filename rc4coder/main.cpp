#include <Windows.h>
#include <tchar.h>

#include <stdio.h>

#include "cryptrc4.h"

UINT CopySuspiciousFile(const TCHAR *filename0, const TCHAR *filename1, BYTE *buffer, UINT buffersize)
{
	HANDLE hfile0;
	HANDLE hfile1;
	DWORD numberofbytes;
	DWORD i;
	UINT result = 0;

	hfile0 = CreateFile(filename0, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hfile0 != INVALID_HANDLE_VALUE)
	{
		hfile1 = CreateFile(filename1, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hfile1 != INVALID_HANDLE_VALUE)
		{
			while (ReadFile(hfile0, buffer, buffersize, &numberofbytes, NULL) && numberofbytes > 0)
			{
				int out_len;
				CryptRC4(buffer, numberofbytes, (const unsigned char *)"ABCDEFG", 7, buffer, &out_len);

				if (WriteFile(hfile1, buffer, out_len, &numberofbytes, NULL) && out_len == numberofbytes)
				{
					result += numberofbytes;
				}
				else
				{
					break;
				}
			}

			CloseHandle(hfile1);
		}

		CloseHandle(hfile0);
	}

	return(result);
}

unsigned int RestoreFiles(TCHAR *filename0, UINT filenamelength0, UINT filenamesize0, 
	TCHAR *filename1, UINT filenamelength1, UINT filenamesize1, WIN32_FIND_DATA *pfd, BYTE *buffer, UINT buffersize)
{
	HANDLE hfind;
	unsigned int result = 0;
	unsigned int l;

	if (filenamelength0 && filename0[filenamelength0 - 1] != L'\\')
	{
		filename0[filenamelength0++] = L'\\';
	}
	if (filenamelength1 && filename0[filenamelength1 - 1] != L'\\')
	{
		filename1[filenamelength1++] = L'\\';
	}
	filename0[filenamelength0 + 0] = _T('*');
	filename0[filenamelength0 + 1] = _T('.');
	filename0[filenamelength0 + 2] = _T('*');
	filename0[filenamelength0 + 3] = _T('\0');
	hfind = FindFirstFile(filename0, pfd);
	if (hfind != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (_tcscmp(pfd->cFileName, _T(".")) != 0 && _tcscmp(pfd->cFileName, _T("..")) != 0)
			{
				l = _tcslen(pfd->cFileName);

				if (filenamelength0 + l < filenamesize0 && filenamelength1 + l < filenamesize1)
				{
					wcscpy(filename0 + filenamelength0, pfd->cFileName);
					wcscpy(filename1 + filenamelength1, pfd->cFileName);

					if (pfd->dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)
					{
						if (filenamelength0 + l + 5 < filenamesize0 && filenamelength1 + l + 1 < filenamesize1)
						{
							CreateDirectory(filename1, NULL);
							result += RestoreFiles(filename0, filenamelength0 + l, filenamesize0,
								filename1, filenamelength1 + l, filenamesize1, pfd, buffer, buffersize);
						}
					}
					else
					{
						CopySuspiciousFile(filename0, filename1, buffer, buffersize);

						result++;
					}
				}
			}
		} while (FindNextFile(hfind, pfd));
		FindClose(hfind);
	}

	return(result);
}

int _tmain(int argc, TCHAR *argv[])
{
	WIN32_FIND_DATA wfd;
	BYTE buffer[65536];
	WCHAR filename0[1024];
	WCHAR filename1[1024];
	UINT filenamelength0;
	UINT filenamelength1;
	unsigned int count;

	if (argc > 2)
	{
		wcscpy(filename0, argv[1]);
		filenamelength0 = wcslen(filename0);

		wcscpy(filename1, argv[2]);
		filenamelength1 = wcslen(filename1);

		count = RestoreFiles(filename0, filenamelength0, sizeof(filename0) / sizeof(filename0[0]),
			filename1, filenamelength1, sizeof(filename1) / sizeof(filename1[0]), &wfd, buffer, sizeof(buffer));

		printf("Total %d\r\n", count);
	}

	return(0);
}