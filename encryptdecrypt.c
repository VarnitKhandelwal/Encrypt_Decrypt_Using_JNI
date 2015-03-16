JNIEXPORT void JNICALL Java_com_verizon_udmclient_util_DbJni_encryptMessage
  (JNIEnv *env, jobject jobj, jstring message)
{
	
	const char *_message;
	_message = (*env)->GetStringUTFChars(env, message, &iscopy);

	printf("Generating RSA (%d bits) r...", KEY_LENGTH);
	fgets(msg, KEY_LENGTH - 1, stdin);
	msg[strlen(msg)] = '\0';
	
	// Encrypt the message
	//keyPair = RSA_generate_key(2048, 3, NULL, NULL);
	
	//r = RSA_new();
	encrypt = malloc(RSA_size(r));

	printf("Encrypted Message is: %s", encrypt);
	//int encrypt_len;
	err = malloc(130);
	
	printf("Generating RSA (%d bits) r...", KEY_LENGTH);

	if ((encrypt_len = RSA_public_encrypt(strlen(msg) + 1, (unsigned char*) msg,
				(unsigned char*) encrypt, r, RSA_PKCS1_OAEP_PADDING)) == -1) {
			ERR_load_crypto_strings();
			LOGD("gen rsa9a");
			ERR_error_string(ERR_get_error(), err);
			LOGD("gen rsa10");
			LOGD(stderr, "Error encrypting message: %s\n", err);
			goto free_stuff;
			//RSA_free(r);
	}

	//#ifdef WRITE_TO_FILE
	// Write the encrypted message to a file
	
	FILE *encryptFile = fopen("/sdcard/encrypt.txt", "w");
  fwrite(encrypt, sizeof(*encrypt), RSA_size(r), encryptFile);
	fclose(encryptFile);

	free_stuff: RSA_free(r);
	BIO_free_all(pub);
	BIO_free_all(pri);
	free(pri_key);
	free(pub_key);
	free(encrypt);
	free(decrypt);
	free(err);

}


JNIEXPORT void JNICALL Java_com_verizon_udmclient_util_DbJni_decryptMessage
  (JNIEnv *env, jobject jobj, jstring message)
{
	// Read it back
	//	printf("Reading back encrypted message and attempting decryption...\n");
	char *encrypt = NULL;
	char *decrypt = NULL; // Decrypted message

	r = RSA_new();
	encrypt = malloc(RSA_size(r));

	FILE *encryptFile = fopen("/sdcard/encrypt.txt", "r");
	fread(encrypt, sizeof(*encrypt), RSA_size(r), encryptFile);

		char buf[1000];
		while (fgets(buf, 1000, encryptFile) != NULL)
			printf("Buffer is: %s", buf);
		fclose(encryptFile);
	//#endif
	LOGD("gen rsa12d");

	// Decrypt it
	decrypt = malloc(encrypt_len);
	LOGD("Encrypt_len value is %d", encrypt_len);
	LOGD("gen rsa12e");
	if (RSA_private_decrypt(encrypt_len, (unsigned char*) encrypt,
			(unsigned char*) decrypt, r, RSA_PKCS1_OAEP_PADDING) == -1) {
		ERR_load_crypto_strings();
		ERR_error_string(ERR_get_error(), err);
		printf("Error decrypting message: %s\n", err);
		printf("Generating RSA (%d bits) r...", KEY_LENGTH);
		goto free_stuff;
	}

	//#ifdef WRITE_TO_FILE
	// Write the encrypted message to a file
	FILE *decryptFile = fopen("/sdcard/decrypt.txt", "w");
	fwrite(decrypt, sizeof(*decrypt), strlen(decrypt), decryptFile);
	fclose(decryptFile);

	printf("Decrypted Message is: %s\n", decrypt);

		free_stuff: RSA_free(r);
		BIO_free_all(pub);
		BIO_free_all(pri);
		free(pri_key);
		free(pub_key);
		free(encrypt);
		free(decrypt);
		free(err);
}
