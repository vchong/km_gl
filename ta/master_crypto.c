/*
 *
 * Copyright (C) 2017 GlobalLogic
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "master_crypto.h"

//Master key for encryption/decryption of all CA's keys,
//and also used as HBK during attestation
static uint8_t objID[] = {0xa7U, 0x62U, 0xcfU, 0x11U};
static uint8_t iv[KEY_LENGTH];

TEE_Result TA_open_secret_key(TEE_ObjectHandle *secretKey)
{
	static TEE_ObjectHandle masterKey = TEE_HANDLE_NULL;
	TEE_Result res = TEE_SUCCESS;
	TEE_Attribute attrs[1];
	uint8_t keyData[KEY_LENGTH];
	uint32_t readSize = 0;
	TEE_ObjectHandle object = TEE_HANDLE_NULL;

	if (masterKey != TEE_HANDLE_NULL) {
		*secretKey = masterKey;
		return TEE_SUCCESS;
	}

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
			objID, sizeof(objID),
			TEE_DATA_FLAG_ACCESS_READ, &object);

	if (res == TEE_SUCCESS) {
		//Key size is fixed
		res = TEE_ReadObjectData(object, keyData, sizeof(keyData), &readSize);
		if (res != TEE_SUCCESS || readSize != KEY_LENGTH) {
			EMSG("Failed to read key, res = %x", res);
			goto close;
		}

		//IV size is fixed
		res = TEE_ReadObjectData(object, iv, sizeof(iv), &readSize);
		if (res != TEE_SUCCESS || readSize != KEY_LENGTH) {
			EMSG("Failed to read IV, res = %x", res);
			goto close;
		}

		TEE_InitRefAttribute(&attrs[0], TEE_ATTR_SECRET_VALUE,
				keyData, sizeof(keyData));

		res = TEE_AllocateTransientObject(TEE_TYPE_AES, KEY_SIZE, &masterKey);
		if (res == TEE_SUCCESS) {
			res = TEE_PopulateTransientObject(masterKey, attrs,
					sizeof(attrs)/sizeof(TEE_Attribute));
			if (res != TEE_SUCCESS) {
				EMSG("Failed to populate transient object, res = %x", res);
			}
		} else {
			EMSG("Failed to allocate transient object, res = %x", res);
		}

close:
		TEE_CloseObject(object);

	} else {
		EMSG("Failed to open a secret persistent key, res = %x", res);
		masterKey = TEE_HANDLE_NULL;
	}

	if (res == TEE_SUCCESS) {
		*secretKey = masterKey;
	}

	return res;
}

TEE_Result TA_create_secret_key(void)
{
	TEE_Result res;
	TEE_ObjectHandle object = TEE_HANDLE_NULL;
	uint8_t keyData[KEY_LENGTH];

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				objID, sizeof(objID),
				TEE_DATA_FLAG_ACCESS_READ, &object);

	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		//No such key, create it
		TEE_GenerateRandom(keyData, sizeof(keyData));
		TEE_GenerateRandom((void *)iv, sizeof(iv));

		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
				objID, sizeof(objID),
				TEE_DATA_FLAG_ACCESS_WRITE,
				TEE_HANDLE_NULL, NULL, 0U, &object);

		if (res != TEE_SUCCESS) {
			EMSG("Failed to create a secret persistent key, res = %x", res);
			goto error;
		}

		res = TEE_WriteObjectData(object, (void *)keyData, sizeof(keyData));
		if (res != TEE_SUCCESS) {
			EMSG("Failed to write key data, res = %x", res);
			goto error;
		}

		res = TEE_WriteObjectData(object, (void *)iv, sizeof(iv));
		if (res != TEE_SUCCESS) {
			EMSG("Failed to write IV, res = %x", res);
			goto error;
		}

error:
		(res == TEE_SUCCESS) ?
				TEE_CloseObject(object) :
				TEE_CloseAndDeletePersistentObject(object);

	} else if (res == TEE_SUCCESS) {
		//Key already exits
		TEE_CloseObject(object);
	} else {
		//Something wrong...
		EMSG("Failed to open secret key, res=%x", res);
	}

	return res;
}

TEE_Result TA_execute(uint8_t *data, const size_t size, const uint32_t mode)
{
	uint8_t *outbuf = NULL;
	uint32_t outbuf_size = size;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectInfo info;
	TEE_Result res;
	TEE_ObjectHandle secretKey = TEE_HANDLE_NULL;

	res = TA_open_secret_key(&secretKey);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to read secret key");
		goto exit;
	}
	outbuf = TEE_Malloc(size, TEE_MALLOC_FILL_ZERO);
	if (!outbuf) {
		EMSG("failed to allocate memory for out buffer");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}
	if (size % BLOCK_SIZE != 0) {
		/* check size alignment */
		EMSG("Size alignment check failed");
		res = KM_ERROR_UNKNOWN_ERROR;
		goto exit;
	}
	TEE_GetObjectInfo1(secretKey, &info);

	res = TEE_AllocateOperation(&op, TEE_ALG_AES_CBC_NOPAD, mode, info.maxKeySize);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate AES operation, res=%x", res);
		goto exit;
	}

	//Use persistent key objects
	res = TEE_SetOperationKey(op, secretKey);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to set secret key, res=%x", res);
		goto free_op;
	}
	TEE_CipherInit(op, iv, sizeof(iv));
	if (res == TEE_SUCCESS && size > 0)
		res = TEE_CipherDoFinal(op, data, size, outbuf, &outbuf_size);
	if (res != TEE_SUCCESS)
		EMSG("Error TEE_CipherDoFinal res=%x", res);
	else
		TEE_MemMove(data, outbuf, size);
free_op:
	if (op != TEE_HANDLE_NULL)
		TEE_FreeOperation(op);
exit:
	if (outbuf != NULL)
		TEE_Free(outbuf);
	return res;
}

TEE_Result TA_encrypt(uint8_t *data, const size_t size)
{
	return TA_execute(data, size, TEE_MODE_ENCRYPT);
}

TEE_Result TA_decrypt(uint8_t *data, const size_t size)
{
	return TA_execute(data, size, TEE_MODE_DECRYPT);
}

void TA_free_master_key(void)
{
	TEE_ObjectHandle secretKey = TEE_HANDLE_NULL;
	if (TA_open_secret_key(&secretKey) == TEE_SUCCESS) {
		TEE_FreeTransientObject(secretKey);
	}
}
