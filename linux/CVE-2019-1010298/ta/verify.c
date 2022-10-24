/*
 * Copyright (c) 2019, Ren Kimura <rkx1209dev@gmail.com>
 * This is simple proof of concept TA.
 * All rights reserved.
 */
 
#include <inttypes.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <verify.h>

static TEE_Result asymm_verify(void *session, uint32_t param_types,
				TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);				
				
	size_t dig_sz, sig_len;
	void *digest, *signature;
	TEE_Attribute* param;
	uint32_t param_sz;
	
	TEE_Result res = TEE_SUCCESS;
	TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
	
	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_AllocateOperation(&op_handle, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1, TEE_MODE_VERIFY, 512);
	
	if (res != TEE_SUCCESS) {
		EMSG("0x%08x", res);
		goto exit;
	}	
	param = params[0].memref.buffer;
	param_sz 	= params[0].memref.size;

	digest = params[1].memref.buffer;
	dig_sz = params[1].memref.size;

	signature = params[2].memref.buffer;
	sig_len 	= params[2].memref.size;


	/*
	 * Verify Message Digest Signature
	 */
	res = TEE_AsymmetricVerifyDigest(op_handle, param, param_sz, digest, dig_sz, signature, sig_len);

exit:
	if (op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(op_handle);
	return res;
}


TEE_Result TA_CreateEntryPoint(void)
{
	/* Nothing to do */
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	/* Nothing to do */
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
					TEE_Param __unused params[4],
					void __unused **session)
{
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session)
{
}

TEE_Result TA_InvokeCommandEntryPoint(void *session,
					uint32_t cmd,
					uint32_t param_types,
					TEE_Param params[4])
{
	switch (cmd) {
	case TA_ASYMM_VERIFY:
		return asymm_verify(session, param_types, params);
	default:
		EMSG("Command ID 0x%x is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
