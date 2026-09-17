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

#ifndef _CRYPT_H
#define _CRYPT_H

#include <windows.h>
#include <Wincrypt.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef BUILDING_LIBRARY

#ifdef _WIN32
#define CRYPTER_EXPORT __declspec(dllexport)
#else
#define CRYPTER_EXPORT __attribute__ ((visibility ("protected")))
#endif

#else

#define CRYPTER_EXPORT

#endif /* BUILDING_LIBRARY */

struct FileHeaderNew
{
    uint8_t mysteryData[64];
    uint32_t dataSize;
    uint32_t logoSize;
    uint32_t descSize;
    uint32_t serialLength;
    uint8_t hash[64];
    uint8_t fileTypeString[32];
    uint8_t gameVersionString[32];
};

struct FileHeaderOld
{
    uint8_t mysteryData[64];
    uint32_t dataSize;
    uint32_t logoSize;
    uint32_t descSize;
    uint32_t serialLength;
    uint8_t hash[64];
    uint8_t fileTypeString[32];
};

struct FileDescriptorNew
{
    uint8_t *encryptionHeader;
    struct FileHeaderNew *fileHeader;

    uint8_t *description;
    uint8_t *logo;
    uint8_t *data;
    uint8_t *serial;
};

struct FileDescriptorOld
{
    uint8_t *encryptionHeader;
    struct FileHeaderOld *fileHeader;

    uint8_t *description;
    uint8_t *logo;
    uint8_t *data;
    uint8_t *serial;
};

struct FileDescriptor15
{
    uint32_t dataSize;
    unsigned char startByte;
    uint32_t chunk0Size; //384
    uint32_t chunk1Size;
    uint32_t chunk2Size;

    uint8_t* chunk0; //Fixed length "Edit file" string
    uint8_t* chunk1lenBytes; //4 bytes that encode length of chunk 1
    uint8_t* chunk1; //PNG
    uint8_t* chunk2lenBytes; //4 bytes that encode length of chunk 2
    uint8_t* data; //Main edit data (chunk 2)
};

enum CrypterOpResult
{
    UNKNOWN = -1, // Couldn't identify failure or a general failure
    OK = 0, // File read successfully.
    READ_FILE_STAT_FAILED, // stat() failed
    INVALID_ARGUMENT, // One or more arguments are invalid or null
    OPEN_FAILED, // Failed to open the file (with fopen)
    ALLOC_FAILED, // Failed to allocate memory for the file content (with malloc)
};

#pragma region Utility functions

int32_t bitsToInt32(const unsigned char* bits, bool little_endian);
void getChunkSizes(const uint8_t*, int*, int);
void generateHeader(char* input, char* output, int* chunkSize, int outSize, const char startByte);
uint32_t md5(uint8_t* input, int inputLen, uint8_t* computedHash);

#pragma endregion

#pragma region Encrypt Decrypt functions

enum CrypterOpResult CRYPTER_EXPORT createFileDescriptorNew(struct FileDescriptorNew *outDesc);
void CRYPTER_EXPORT destroyFileDescriptorNew(struct FileDescriptorNew *desc);
enum CrypterOpResult CRYPTER_EXPORT createFileDescriptorOld(struct FileDescriptorOld *outDesc);
void CRYPTER_EXPORT destroyFileDescriptorOld(struct FileDescriptorOld *desc);
enum CrypterOpResult CRYPTER_EXPORT createFileDescriptor15(struct FileDescriptor15 *outDesc);
void CRYPTER_EXPORT destroyFileDescriptor15(struct FileDescriptor15 *desc);

enum CrypterOpResult CRYPTER_EXPORT decryptWithKeyNew(struct FileDescriptorNew *descriptor, const uint8_t *input, const char *masterKey);
enum CrypterOpResult CRYPTER_EXPORT encryptWithKeyNew(const struct FileDescriptorNew *descriptor, int *size, const char *masterKey, uint8_t* encryptedResult);
enum CrypterOpResult CRYPTER_EXPORT decryptWithKeyOld(struct FileDescriptorOld *descriptor, const uint8_t *input, const char *masterKey);
enum CrypterOpResult CRYPTER_EXPORT encryptWithKeyOld(const struct FileDescriptorOld *descriptor, int *size, const char *masterKey, uint8_t* encryptedResult);
enum CrypterOpResult CRYPTER_EXPORT decryptFile15(struct FileDescriptor15 *descriptor, const uint8_t *input);
enum CrypterOpResult CRYPTER_EXPORT encryptFile15(const struct FileDescriptor15 *descriptor, int *outputLen, uint8_t* encryptedResult);

#pragma endregion

#pragma region Read Write functions

/// <summary>
/// Reads a file completely into a dynamically allocated buffer.
/// </summary>
/// <param name="path">Path to the file (<b>must be in UTF-8 format</b>).</param>
/// <param name="outData">Pointer to a <c>uint8_t*</c> that will receive the allocated file buffer. 
/// <para><i>Note: The caller is responsible for freeing this memory.</i></para></param>
/// <param name="sizePtr">Optional. Pointer to a <c>uint32_t</c> that receives the size of the file in bytes. Pass <c>NULL</c> if not needed.</param>
/// <returns>
/// An <c>OpResult</c> indicating the outcome
/// </returns>
enum CrypterOpResult CRYPTER_EXPORT readFile(const char *path, uint8_t** outData, uint32_t *sizePtr);

/// <summary>
/// Writes a binary buffer to a specified file path. Overwrites the file if it already exists.
/// </summary>
/// <param name="path">Path to the file to create or overwrite (<b>must be in UTF-8 format</b>).</param>
/// <param name="data">Pointer to the constant <c>uint8_t</c> buffer containing the data to be written.</param>
/// <param name="size">The total number of bytes to write from the buffer.</param>
/// <returns>
/// An <c>OpResult</c> indicating the outcome
/// </returns>
enum CrypterOpResult CRYPTER_EXPORT writeFile(const char* path, const uint8_t* data, int size);

#pragma endregion

#ifdef __cplusplus
}
#endif

#endif /* _CRYPT_H */
