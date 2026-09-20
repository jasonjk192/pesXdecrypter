/*
 * This file contains code derived from:
 *   https://github.com/the4chancup/pesXdecrypter
 *   https://github.com/the4chancup/libpes15crypter
 *
 * The original pesXdecrypter code is released under the Unlicense.
 * See licenses/LICENSE - pesXdecrypter.txt
 *
 * Code derived from libpes15crypter is Copyright (c) 2025 The 4chan Cup and is distributed under its accompanying license.
 * See licenses/LICENSE - libpes15crypter.md
 *
 * This file has been modified from the original sources to integrate the decrypter implementations in this project.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>

#include "mt19937ar.h"
#include "crypt.h"
#include "masterkey.h"

#define ENCRYPTION_HEADER_SIZE 320
#define HEADER_BYTES_15 49

#define MD5LEN 16
#define BUFSIZE 1024

#pragma region Utility functions

int32_t bitsToInt32(const unsigned char* bits, bool little_endian)
{
	int32_t result = 0;
	if (little_endian)
		for (int n = sizeof(result); n >= 0; n--)
			result = (result << 8) + bits[n];
	else
		for (unsigned n = 0; n < sizeof(result); n++)
			result = (result << 8) + bits[n];
	return result;
}

void getChunkSizes(const uint8_t* input, int* array, int arrayLen)
{
	if (arrayLen < 3)
		return;
	array[0] = 384;
	array[1] = bitsToInt32(&input[array[0]], true);
	array[2] = bitsToInt32(&input[array[0] + array[1] + 4], true);
	return;
}

void generateHeader(char* input, char* output, int* chunkSize, int outSize, const char startByte)
{
	output[0] = startByte;
	uint8_t array[MD5LEN];
	md5(input, chunkSize[0], array);
	memcpy_s(&output[1], outSize - 1, array, MD5LEN);
	md5(&input[chunkSize[0] + 4], chunkSize[1], array);
	memcpy_s(&output[17], outSize - 17, array, MD5LEN);
	md5(&input[chunkSize[0] + chunkSize[1] + 8], chunkSize[2], array);
	memcpy_s(&output[33], outSize - 33, array, MD5LEN);
}

uint32_t md5(uint8_t* input, int inputLen, uint8_t* computedHash)
{
	uint32_t dwStatus = 0;
	BOOL bResult = FALSE;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	DWORD cbHash = 0;

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %lu\n", (unsigned long)dwStatus);
		return dwStatus;
	}

	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		dwStatus = GetLastError();
		printf("CryptCreateHash failed: %lu\n", (unsigned long)dwStatus);
		CryptReleaseContext(hProv, 0);
		return dwStatus;
	}

	if (!CryptHashData(hHash, input, (DWORD)inputLen, 0))
	{
		dwStatus = GetLastError();
		printf("CryptHashData failed: %lu\n", (unsigned long)dwStatus);
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return dwStatus;
	}

	cbHash = MD5LEN;
	if (!CryptGetHashParam(hHash, HP_HASHVAL, computedHash, &cbHash, 0))
	{
		dwStatus = GetLastError();
		printf("CryptGetHashParam failed: %lu\n", (unsigned long)dwStatus);
	}
	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);

	return dwStatus;
}

uint32_t rol(uint32_t a, uint32_t shift)
{
	return (a << shift) | (a >> (32 - shift));
}

uint32_t ror(uint32_t a, uint32_t shift)
{
	return (a >> shift) | (a << (32 - shift));
}

void xorRepeatingBlocks(uint8_t* output, const uint8_t* input, int length)
{
	for (int i = 0; i < length; ++i)
		output[i & 63] ^= input[i];
}

void xorWithLongParam(const uint8_t* input, uint8_t* output, uint64_t param)
{
	const uint64_t* input64 = (uint64_t*)input;
	uint64_t* output64 = (uint64_t*)output;

	for (int i = 0; i < 8; ++i)
		output64[i] = input64[i] ^ param;
}

void reverseLongs(uint8_t* output, const uint8_t* input)
{
	for (int i = 0; i < 8; ++i)
		for (int j = 0; j < 8; ++j)
			output[i * 8 + j] = input[i * 8 + 7 - j];
}

void cryptStream(uint8_t* output, const uint8_t* key, const uint8_t* input, int length)
{
	uint32_t* input32 = (uint32_t*)input;
	uint32_t* output32 = (uint32_t*)output;

	init_by_array((uint32_t*)key, 16);
	uint32_t c0 = genrand_int32();
	uint32_t c1 = genrand_int32();
	uint32_t c2 = genrand_int32();
	uint32_t c3 = genrand_int32();

	for (int i = 0; i < length / 4; ++i) {
		uint32_t c4 = genrand_int32();

		output32[i] = c4 ^ c3 ^ c2 ^ c1 ^ c0 ^ input32[i];

		c0 = ror(c1, 15);
		c1 = rol(c2, 11);
		c2 = rol(c3, 7);
		c3 = ror(c4, 13);
	}
	if (length & 3) {
		uint32_t rest;
		memcpy(&rest, &input[length & (~3)], length & 3);

		rest ^= genrand_int32() ^ c3 ^ c2 ^ c1 ^ c0;

		memcpy(&output[length & (~3)], &rest, length & 3);
	}
}

void cryptHeader(uint8_t* output, const uint8_t* input, const uint8_t* key)
{
	uint8_t headerKey[64], shuffledMasterKey[64];

	memcpy(headerKey, &input[256], 64);
	reverseLongs(shuffledMasterKey, key);
	xorRepeatingBlocks(headerKey, shuffledMasterKey, 64);
	cryptStream(output, headerKey, input, ENCRYPTION_HEADER_SIZE);
	memcpy(&output[256], &input[256], 64);
}

static void initDescriptorOld(struct FileDescriptorOld* descriptor)
{
	descriptor->encryptionHeader = NULL;
	descriptor->fileHeader = NULL;
	descriptor->data = NULL;
	descriptor->logo = NULL;
	descriptor->description = NULL;
	descriptor->serial = NULL;
}

static void initDescriptorNew(struct FileDescriptorNew* descriptor)
{
	descriptor->encryptionHeader = NULL;
	descriptor->fileHeader = NULL;
	descriptor->data = NULL;
	descriptor->logo = NULL;
	descriptor->description = NULL;
	descriptor->serial = NULL;
}

static void initDescriptor15(struct FileDescriptor15* descriptor)
{
	descriptor->data = NULL;
	descriptor->chunk0 = NULL;
	descriptor->chunk1 = NULL;
	descriptor->chunk0Size = 0;
	descriptor->chunk1lenBytes = NULL;
	descriptor->chunk1Size = 0;
	descriptor->chunk2lenBytes = NULL;
	descriptor->chunk2Size = 0;
}

#pragma endregion

#pragma region Encrypt Decrypt functions

enum CrypterOpResult decryptWithKeyOld(struct FileDescriptorOld* descriptor, const uint8_t* input, const char* masterKey)
{
#ifdef DEBUG
	if(!descriptor) fprintf(stderr, "decryptWithKeyOld: descriptor is empty\n");
	if(!input) fprintf(stderr, "decryptWithKeyOld: input is empty\n");
	if(!masterKey) fprintf(stderr, "decryptWithKeyOld: masterKey is empty\n"); 
#endif

	if (!descriptor || !input || !masterKey)
		return INVALID_ARGUMENT;
	initDescriptorOld(descriptor);

	descriptor->encryptionHeader = (uint8_t*)malloc(ENCRYPTION_HEADER_SIZE);
	if (descriptor->encryptionHeader == NULL)
	{
		destroyFileDescriptorOld(descriptor);
		return ALLOC_FAILED;
	}

	descriptor->fileHeader = (struct FileHeaderOld*)malloc(sizeof(struct FileHeaderOld));
	if (descriptor->fileHeader == NULL)
	{
		destroyFileDescriptorOld(descriptor);
		return ALLOC_FAILED;
	}

	cryptHeader(descriptor->encryptionHeader, input, masterKey);
	input += ENCRYPTION_HEADER_SIZE;

	uint8_t rollingKey[64], intermediateKey[64];
	memcpy(rollingKey, descriptor->encryptionHeader, 64);
	xorRepeatingBlocks(rollingKey, &descriptor->encryptionHeader[64], 256);

	xorWithLongParam(rollingKey, intermediateKey, sizeof(struct FileHeaderOld));
	cryptStream((uint8_t*)descriptor->fileHeader, intermediateKey, input, sizeof(struct FileHeaderOld));
	input += sizeof(struct FileHeaderOld);

	descriptor->data = (uint8_t*)malloc(descriptor->fileHeader->dataSize);
	if (descriptor->data == NULL)
	{
		destroyFileDescriptorOld(descriptor);
		return ALLOC_FAILED;
	}

	descriptor->logo = (uint8_t*)malloc(descriptor->fileHeader->logoSize);
	if (descriptor->logo == NULL)
	{
		destroyFileDescriptorOld(descriptor);
		return ALLOC_FAILED;
	}

	descriptor->description = (uint8_t*)malloc(descriptor->fileHeader->descSize);
	if (descriptor->description == NULL)
	{
		destroyFileDescriptorOld(descriptor);
		return ALLOC_FAILED;
	}

	descriptor->serial = (uint8_t*)malloc(descriptor->fileHeader->serialLength * 2);
	if (descriptor->serial == NULL)
	{
		destroyFileDescriptorOld(descriptor);
		return ALLOC_FAILED;
	}

	xorWithLongParam(rollingKey, intermediateKey, 0);
	cryptStream(descriptor->description, intermediateKey, input, descriptor->fileHeader->descSize);
	input += descriptor->fileHeader->descSize;


	xorWithLongParam(rollingKey, intermediateKey, 1);
	cryptStream(descriptor->logo, intermediateKey, input, descriptor->fileHeader->logoSize);
	input += descriptor->fileHeader->logoSize;

	xorWithLongParam(rollingKey, intermediateKey, 2);
	cryptStream(descriptor->data, intermediateKey, input, descriptor->fileHeader->dataSize);
	input += descriptor->fileHeader->dataSize;

	xorWithLongParam(rollingKey, intermediateKey, 3);
	cryptStream(descriptor->serial, intermediateKey, input, descriptor->fileHeader->serialLength * 2);

	return OK;
}

enum CrypterOpResult decryptWithKeyNew(struct FileDescriptorNew* descriptor, const uint8_t* input, const char* masterKey)
{
#ifdef DEBUG
	if (!descriptor) fprintf(stderr, "decryptWithKeyNew: descriptor is empty\n");
	if (!input) fprintf(stderr, "decryptWithKeyNew: input is empty\n");
	if (!masterKey) fprintf(stderr, "decryptWithKeyNew: masterKey is empty\n");
#endif

	if (!descriptor || !input || !masterKey)
		return INVALID_ARGUMENT;
	initDescriptorNew(descriptor);

	descriptor->encryptionHeader = (uint8_t*)malloc(ENCRYPTION_HEADER_SIZE);
	if (descriptor->encryptionHeader == NULL)
	{
		destroyFileDescriptorNew(descriptor);
		return ALLOC_FAILED;
	}

	descriptor->fileHeader = (struct FileHeaderNew*)malloc(sizeof(struct FileHeaderNew));
	if (descriptor->fileHeader == NULL)
	{
		destroyFileDescriptorNew(descriptor);
		return ALLOC_FAILED;
	}

	cryptHeader(descriptor->encryptionHeader, input, masterKey);
	input += ENCRYPTION_HEADER_SIZE;

	uint8_t rollingKey[64], intermediateKey[64];
	memcpy(rollingKey, descriptor->encryptionHeader, 64);
	xorRepeatingBlocks(rollingKey, &descriptor->encryptionHeader[64], 256);

	xorWithLongParam(rollingKey, intermediateKey, sizeof(struct FileHeaderNew));
	cryptStream((uint8_t*)descriptor->fileHeader, intermediateKey, input, sizeof(struct FileHeaderNew));
	input += sizeof(struct FileHeaderNew);

	descriptor->data = (uint8_t*)malloc(descriptor->fileHeader->dataSize);
	if (descriptor->data == NULL)
	{
		destroyFileDescriptorNew(descriptor);
		return ALLOC_FAILED;
	}

	descriptor->logo = (uint8_t*)malloc(descriptor->fileHeader->logoSize);
	if (descriptor->logo == NULL)
	{
		destroyFileDescriptorNew(descriptor);
		return ALLOC_FAILED;
	}

	descriptor->description = (uint8_t*)malloc(descriptor->fileHeader->descSize);
	if (descriptor->description == NULL)
	{
		destroyFileDescriptorNew(descriptor);
		return ALLOC_FAILED;
	}

	descriptor->serial = (uint8_t*)malloc(descriptor->fileHeader->serialLength * 2);
	if (descriptor->serial == NULL)
	{
		destroyFileDescriptorNew(descriptor);
		return ALLOC_FAILED;
	}

	xorWithLongParam(rollingKey, intermediateKey, 0);
	cryptStream(descriptor->description, intermediateKey, input, descriptor->fileHeader->descSize);
	input += descriptor->fileHeader->descSize;

	xorWithLongParam(rollingKey, intermediateKey, 1);
	cryptStream(descriptor->logo, intermediateKey, input, descriptor->fileHeader->logoSize);
	input += descriptor->fileHeader->logoSize;

	xorWithLongParam(rollingKey, intermediateKey, 2);
	cryptStream(descriptor->data, intermediateKey, input, descriptor->fileHeader->dataSize);
	input += descriptor->fileHeader->dataSize;

	xorWithLongParam(rollingKey, intermediateKey, 3);
	cryptStream(descriptor->serial, intermediateKey, input, descriptor->fileHeader->serialLength * 2);

	return OK;
}

enum CrypterOpResult decryptFile15(struct FileDescriptor15* descriptor, const uint8_t* input)
{
#ifdef DEBUG
	if (!descriptor) fprintf(stderr, "decryptFile15: descriptor is empty\n");
	if (!input) fprintf(stderr, "decryptFile15: input is empty\n");
	if (!masterKey) fprintf(stderr, "decryptFile15: masterKey is empty\n");
#endif

	if (!descriptor || !input)
		return INVALID_ARGUMENT;
	initDescriptor15(descriptor);

	//First 49 bytes are the header section, so reduce length by that amount
	descriptor->dataSize = descriptor->dataSize - HEADER_BYTES_15;

	//Data is formatted in 3 chunks, get their sizes
	int chunkSizes[3] = { 0 };
	getChunkSizes(&input[HEADER_BYTES_15], chunkSizes, 3);

	//The decrypt/encrypt algo is initialized from input[0], so save that in descriptor
	descriptor->startByte = input[0];
	descriptor->chunk1Size = chunkSizes[1];
	descriptor->chunk2Size = chunkSizes[2];

	//Place encrypted data in a temporary structure for decryption
	uint8_t* tmpData = malloc(descriptor->dataSize);
	if (tmpData == NULL)
	{
		destroyFileDescriptor15(descriptor);
		return ALLOC_FAILED;
	}

	memcpy_s(tmpData, descriptor->dataSize, &input[HEADER_BYTES_15], descriptor->dataSize);

	//Then do the decryption operation on descriptor->data, initialized from startByte
	int num = 0;
	int num2 = 0;
	for (int i = 0; i < 3; i++)
	{
		int num3 = descriptor->startByte;
		for (int j = 0; j < chunkSizes[i]; j++)
		{
			num = num3 * 21 + 7;
			num3 = (num %= 32768);
			tmpData[num2] ^= (uint8_t)(num %= 255);
			num2++;
		}
		num2 += 4; //Skip 4 bytes between each chunk
	}

	//Allocate the necessary memory for the data array and copy it from input to the descriptor (starting from byte 49)
	//uint8_t chunk0[384]; //Fixed length "Edit file" string
	//uint8_t chunk1lenBytes[4]; //4 bytes that encode length of chunk 1
	descriptor->chunk1 = malloc(chunkSizes[1]);
	if (descriptor->chunk1 == NULL)
	{
		destroyFileDescriptor15(descriptor);
		return ALLOC_FAILED;
	}

	//uint8_t chunk2lenBytes[4]; //4 bytes that encode length of chunk 2
	descriptor->data = malloc(chunkSizes[2]);
	if (descriptor->data == NULL)
	{
		destroyFileDescriptor15(descriptor);
		return ALLOC_FAILED;
	}

	//Copy each portion of input data to the corresponding structure in descriptor
	int offset = 0;
	memcpy_s(descriptor->chunk0, chunkSizes[0], &tmpData[offset], chunkSizes[0]);
	offset += chunkSizes[0];
	memcpy_s(descriptor->chunk1lenBytes, 4, &tmpData[offset], 4);
	offset += 4;
	memcpy_s(descriptor->chunk1, chunkSizes[1], &tmpData[offset], chunkSizes[1]);
	offset += chunkSizes[1];
	memcpy_s(descriptor->chunk2lenBytes, 4, &tmpData[offset], 4);
	offset += 4;
	memcpy_s(descriptor->data, chunkSizes[2], &tmpData[offset], chunkSizes[2]);

	free(tmpData);

	return OK;
}

enum CrypterOpResult encryptWithKeyOld(const struct FileDescriptorOld* descriptor, int* size, const char* masterKey, uint8_t* encryptedResult)
{
	*size = ENCRYPTION_HEADER_SIZE
		+ sizeof(struct FileHeaderOld)
		+ descriptor->fileHeader->dataSize
		+ descriptor->fileHeader->logoSize
		+ descriptor->fileHeader->descSize
		+ descriptor->fileHeader->serialLength * 2;

	uint8_t* output = (uint8_t*)malloc(*size);
	if (!output)
		return ALLOC_FAILED;

	cryptHeader(output, descriptor->encryptionHeader, masterKey);
	output += ENCRYPTION_HEADER_SIZE;

	uint8_t rollingKey[64], intermediateKey[64];
	memcpy(rollingKey, descriptor->encryptionHeader, 64);
	xorRepeatingBlocks(rollingKey, &descriptor->encryptionHeader[64], 256);

	xorWithLongParam(rollingKey, intermediateKey, sizeof(struct FileHeaderOld));
	cryptStream(output, intermediateKey, (uint8_t*)descriptor->fileHeader, sizeof(struct FileHeaderOld));
	output += sizeof(struct FileHeaderOld);

	xorWithLongParam(rollingKey, intermediateKey, 0);
	cryptStream(output, intermediateKey, descriptor->description, descriptor->fileHeader->descSize);
	output += descriptor->fileHeader->descSize;

	xorWithLongParam(rollingKey, intermediateKey, 1);
	cryptStream(output, intermediateKey, descriptor->logo, descriptor->fileHeader->logoSize);
	output += descriptor->fileHeader->logoSize;

	xorWithLongParam(rollingKey, intermediateKey, 2);
	cryptStream(output, intermediateKey, descriptor->data, descriptor->fileHeader->dataSize);
	output += descriptor->fileHeader->dataSize;

	xorWithLongParam(rollingKey, intermediateKey, 3);
	cryptStream(output, intermediateKey, descriptor->serial, descriptor->fileHeader->serialLength * 2);

	encryptedResult = output;
	return OK;
}

enum CrypterOpResult encryptWithKeyNew(const struct FileDescriptorNew* descriptor, int* size, const char* masterKey, uint8_t* encryptedResult)
{
	*size = ENCRYPTION_HEADER_SIZE
		+ sizeof(struct FileHeaderNew)
		+ descriptor->fileHeader->dataSize
		+ descriptor->fileHeader->logoSize
		+ descriptor->fileHeader->descSize
		+ descriptor->fileHeader->serialLength * 2;

	uint8_t* output = (uint8_t*)malloc(*size);
	if (!output)
		return ALLOC_FAILED;

	cryptHeader(output, descriptor->encryptionHeader, masterKey);
	output += ENCRYPTION_HEADER_SIZE;

	uint8_t rollingKey[64], intermediateKey[64];
	memcpy(rollingKey, descriptor->encryptionHeader, 64);
	xorRepeatingBlocks(rollingKey, &descriptor->encryptionHeader[64], 256);

	xorWithLongParam(rollingKey, intermediateKey, sizeof(struct FileHeaderNew));
	cryptStream(output, intermediateKey, (uint8_t*)descriptor->fileHeader, sizeof(struct FileHeaderNew));
	output += sizeof(struct FileHeaderNew);

	xorWithLongParam(rollingKey, intermediateKey, 0);
	cryptStream(output, intermediateKey, descriptor->description, descriptor->fileHeader->descSize);
	output += descriptor->fileHeader->descSize;

	xorWithLongParam(rollingKey, intermediateKey, 1);
	cryptStream(output, intermediateKey, descriptor->logo, descriptor->fileHeader->logoSize);
	output += descriptor->fileHeader->logoSize;

	xorWithLongParam(rollingKey, intermediateKey, 2);
	cryptStream(output, intermediateKey, descriptor->data, descriptor->fileHeader->dataSize);
	output += descriptor->fileHeader->dataSize;

	xorWithLongParam(rollingKey, intermediateKey, 3);
	cryptStream(output, intermediateKey, descriptor->serial, descriptor->fileHeader->serialLength * 2);

	encryptedResult = output;
	return OK;
}

enum CrypterOpResult encryptFile15(const struct FileDescriptor15* descriptor, int* outputLen, uint8_t* encryptedResult)
{
	*outputLen = descriptor->dataSize + HEADER_BYTES_15; //Add 49 byte header
	uint8_t* output = (uint8_t*)malloc(*outputLen);
	if (!output)
		return ALLOC_FAILED;

	//Copy each portion of descriptor data to output array
	int offset = HEADER_BYTES_15;
	memcpy_s(&output[offset], descriptor->chunk0Size, descriptor->chunk0, descriptor->chunk0Size);
	offset += descriptor->chunk0Size;
	memcpy_s(&output[offset], 4, descriptor->chunk1lenBytes, 4);
	offset += 4;
	memcpy_s(&output[offset], descriptor->chunk1Size, descriptor->chunk1, descriptor->chunk1Size);
	offset += descriptor->chunk1Size;
	memcpy_s(&output[offset], 4, descriptor->chunk2lenBytes, 4);
	offset += 4;
	memcpy_s(&output[offset], descriptor->chunk2Size, descriptor->data, descriptor->chunk2Size);

	int chunkSizes[3] = { descriptor->chunk0Size, descriptor->chunk1Size, descriptor->chunk2Size };

	generateHeader((char*)&output[HEADER_BYTES_15], (char*)output, chunkSizes, *outputLen, descriptor->startByte);

	//Reverse the decryption, initialized from startByte
	int num = 0;
	int num2 = HEADER_BYTES_15;
	for (int i = 0; i < 3; i++)
	{
		int num3 = descriptor->startByte;
		for (int j = 0; j < chunkSizes[i]; j++)
		{
			num = num3 * 21 + 7;
			num3 = (num %= 32768);
			output[num2] ^= (char)(num %= 255);
			num2++;
		}
		num2 += 4;
	}
	encryptedResult = output;
	return OK;
}

enum CrypterOpResult CRYPTER_EXPORT createFileDescriptorOld(struct FileDescriptorOld** outDesc)
{
	if (!outDesc)
		return INVALID_ARGUMENT;

	struct FileDescriptorOld* result = malloc(sizeof(struct FileDescriptorOld));
	if (!result)
		return ALLOC_FAILED;

	memset(result, 0, sizeof(struct FileDescriptorOld));
	*outDesc = result;
	return OK;
}

enum CrypterOpResult CRYPTER_EXPORT createFileDescriptorNew(struct FileDescriptorNew** outDesc)
{
	if (!outDesc)
		return INVALID_ARGUMENT;

	struct FileDescriptorNew* result = malloc(sizeof(struct FileDescriptorNew));
	if (!result)
		return ALLOC_FAILED;

	memset(result, 0, sizeof(struct FileDescriptorNew));
	*outDesc = result;
	return OK;
}

enum CrypterOpResult CRYPTER_EXPORT createFileDescriptor15(struct FileDescriptor15** outDesc)
{
	if (!outDesc)
		return INVALID_ARGUMENT;

	struct FileDescriptor15* result = malloc(sizeof(struct FileDescriptor15));
	if (!result)
		return ALLOC_FAILED;
	
	memset(result, 0, sizeof(struct FileDescriptor15));
	result->chunk0Size = 384;
	result->chunk0 = malloc(result->chunk0Size);
	if (result->chunk0)
		memset(result->chunk0, 0, result->chunk0Size);
	else
	{
		free(result);
		return ALLOC_FAILED;
	}
		
	result->chunk1lenBytes = malloc(4);
	if (result->chunk1lenBytes)
		memset(result->chunk1lenBytes, 0, 4);
	else
	{
		free(result->chunk0);
		free(result);
		return ALLOC_FAILED;
	}
	result->chunk2lenBytes = malloc(4);
	if (result->chunk2lenBytes)
		memset(result->chunk2lenBytes, 0, 4);
	else
	{
		free(result->chunk0);
		free(result->chunk1lenBytes);
		free(result);
		return ALLOC_FAILED;
	}
	
	*outDesc = result;
	return OK;
}

void CRYPTER_EXPORT destroyFileDescriptorOld(struct FileDescriptorOld* desc)
{
	if (desc->encryptionHeader) free(desc->encryptionHeader);
	if (desc->fileHeader)       free(desc->fileHeader);
	if (desc->description)      free(desc->description);
	if (desc->logo)             free(desc->logo);
	if (desc->data)             free(desc->data);
	if (desc->serial)           free(desc->serial);
	free(desc);
}

void CRYPTER_EXPORT destroyFileDescriptorNew(struct FileDescriptorNew* desc)
{
	if (desc->encryptionHeader) free(desc->encryptionHeader);
	if (desc->fileHeader)       free(desc->fileHeader);
	if (desc->description)      free(desc->description);
	if (desc->logo)             free(desc->logo);
	if (desc->data)             free(desc->data);
	if (desc->serial)           free(desc->serial);
	free(desc);
}

void CRYPTER_EXPORT destroyFileDescriptor15(struct FileDescriptor15* desc)
{
	if (desc->data)             free(desc->data);
	if (desc->chunk1)			free(desc->chunk1);
	free(desc->chunk0);
	free(desc->chunk1lenBytes);
	free(desc->chunk2lenBytes);
	free(desc);
}

#pragma endregion

#pragma region Read Write functions

enum CrypterOpResult CRYPTER_EXPORT readFile(const char* path, uint8_t** outData, uint32_t* sizePtr)
{
#ifdef DEBUG
	if (!path) fprintf(stderr, "readFile: path is empty\n");
	if (!outData) fprintf(stderr, "readFile: outData is empty\n");
#endif

	if (!path || !outData)
		return INVALID_ARGUMENT;
	*outData = NULL;

	FILE* inStream = fopen(path, "rb");
	if (!inStream)
		return OPEN_FAILED;

	struct stat file;
	if (stat(path, &file))
	{
		fclose(inStream);
		return READ_FILE_STAT_FAILED;
	}		
	int size = file.st_size;

	uint8_t* input = (uint8_t*)malloc(size);
	if (!input)
	{
		fclose(inStream);
		return ALLOC_FAILED;
	}

	fread(input, 1, size, inStream);
	fclose(inStream);

	if (sizePtr)
		*sizePtr = size;

	*outData = input;
	return OK;
}

enum CrypterOpResult CRYPTER_EXPORT writeFile(const char* path, const uint8_t* data, int size)
{
#ifdef DEBUG
	if (!path) fprintf(stderr, "writeFile: path is empty\n");
	if (!data) fprintf(stderr, "writeFile: data is empty\n");
#endif

	if (!path || !data)
		return INVALID_ARGUMENT;

	FILE* outStream = fopen(path, "wb");
	if (!outStream)
		return OPEN_FAILED;
		
	fwrite(data, 1, size, outStream);
	fclose(outStream);
	return OK;
}

void CRYPTER_EXPORT freeData(uint8_t* data)
{
	if(!data) free(data);
}

#pragma endregion