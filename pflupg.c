#include "pflupg.h"

void printArray(const unsigned char buf[], unsigned int n) {
	int i;
	for (i = 0; i < n; i++)
	{
		printf("%02X", buf[i]);
	}
	printf("\n");
}

void swap_bytes(unsigned char buf[], unsigned int len) {
	int i;
	char t;
	for(i = 0; i < (len/2); i++) {
		t = buf[i];
		buf[i] = buf[len-i-1];
		buf[len-i-1] = t;
	}
}

int decrypt_upg_signature(unsigned char *sig, unsigned int sig_size, unsigned int pubkey_idx)
{
	const char pkey_fmt[] = "(public-key (rsa (n %M)(e %M)))";
	const char sig_fmt[] = "(data (flags raw) (value %M))";
	gcry_sexp_t sexp_pubkey, sexp_sig, sexp_sig_plain, sexp_sig_token;
	gcry_mpi_t mpi_sig,mpi_modulus, mpi_pubexpo;
	gcry_error_t err = 0;
	unsigned char *plain;
	size_t erroff, plain_size;
	
	swap_bytes(sig, sig_size);
	
	//Create RSA public key S-expression
	if(err = gcry_mpi_scan(&mpi_modulus, GCRYMPI_FMT_HEX, public_keys[pubkey_idx][2], 0, NULL)) {
		fprintf (stderr, "Fail to create mpi from modulus: %s/%s\n", gcry_strsource (err), gcry_strerror (err));
		return -1;
	}
	if(err = gcry_mpi_scan(&mpi_pubexpo, GCRYMPI_FMT_HEX, public_keys[pubkey_idx][1], 0, NULL)) {
		fprintf (stderr, "Fail to create mpi from public exponent: %s/%s\n", gcry_strsource (err), gcry_strerror (err));
		return -1;
	}
	if(err = gcry_sexp_build(&sexp_pubkey, &erroff, pkey_fmt, mpi_modulus, mpi_pubexpo)) {
		fprintf (stderr, "Fail to build public key sexpr: %s/%s\n", gcry_strsource (err), gcry_strerror (err));
		return -1;
	}
	
	//Create signature key S-expression
	if(err = gcry_mpi_scan(&mpi_sig, GCRYMPI_FMT_USG, sig, sig_size, NULL)) {
		fprintf (stderr, "Fail to create mpi from signature: %s/%s\n", gcry_strsource (err), gcry_strerror (err));
		return -1;
	}
	if(err = gcry_sexp_build(&sexp_sig, &erroff, sig_fmt, mpi_sig)) {
		fprintf (stderr, "Fail to build signature sexpr: %s/%s\n", gcry_strsource (err), gcry_strerror (err));
		return -1;
	}
	
	if(err = gcry_pk_encrypt(&sexp_sig_plain, sexp_sig, sexp_pubkey)) {
		fprintf (stderr, "Fail to decrypt signature: %s/%s\n", gcry_strsource (err), gcry_strerror (err));
		return -1;
	}
	
	if(!(sexp_sig_token = gcry_sexp_find_token(sexp_sig_plain, "a", 0))) {
		fprintf (stderr, "Fail to find token in signature: %s/%s\n", gcry_strsource (err), gcry_strerror (err));
		return -1;
	}
	if(gcry_sexp_length(sexp_sig_token) < 2 ) {
		fprintf (stderr, "Error:  signature sexpr length too small\n");
		return -1;
	}
	
	plain = (unsigned char*)gcry_sexp_nth_data(sexp_sig_token, 1, &plain_size);
	if(!plain) {
		fprintf (stderr, "Fail to extract token in signature: %s/%s\n", gcry_strsource (err), gcry_strerror (err));
		return -1;
	}
	
	if(plain_size < 52){
		fprintf (stderr, "Error: decrypted signature too small (%u bytes) !\n", plain_size);
		return -1;
	}
	
	swap_bytes(plain, plain_size);
	memcpy(sig, plain, (plain_size < sig_size ? plain_size : sig_size));
	
	gcry_sexp_release(sexp_pubkey);
	gcry_sexp_release(sexp_sig);
	gcry_sexp_release(sexp_sig_plain);
	gcry_sexp_release(sexp_sig_token);
	
	gcry_mpi_release(mpi_sig);
	gcry_mpi_release(mpi_modulus);
	gcry_mpi_release(mpi_pubexpo);
	
	return 0;
}

int decrypt_upg_data(unsigned char *data, size_t data_size, unsigned char * key, size_t key_size){
	gcry_cipher_hd_t hd;
	gcry_error_t err = 0;
	
	if(err = gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB, 0)){
		fprintf (stderr, "Fail to create AES256 context handle: %s/%s\n", gcry_strsource (err), gcry_strerror (err));
		return -1;
	}
	
	if(err = gcry_cipher_setkey(hd, key, key_size)){
		fprintf (stderr, "Fail to set AES key: %s/%s\n", gcry_strsource (err), gcry_strerror (err));
		return -1;
	}
	
	if(err = gcry_cipher_decrypt(hd, data, data_size, NULL, 0)){
		fprintf (stderr, "Fail to decrypt AES data: %s/%s\n", gcry_strsource (err), gcry_strerror (err));
		return -1;
	}
	
	gcry_cipher_close(hd);
	
	return 0;
}

int read_upg(unsigned char *filename, unsigned char **upg_buf, unsigned long int *upg_size){
	FILE *upg_file;
	upg_header *header;
	signed int upg_header_extra_size;
	size_t result;
	
	upg_file = fopen(filename, "r");
	if(!upg_file) {
		printf("Error opening upg file!\n");
		return -1;
	}
	
	fseek (upg_file , 0 , SEEK_END);
	*upg_size = ftell (upg_file);
	if (*upg_size < sizeof(upg_header)) {
		printf("Error: upg file too small !\n");
		return -1;
	}
	fseek (upg_file, 0, SEEK_SET);
	
	*upg_buf = (unsigned char*) malloc(*upg_size);
	result = fread(*upg_buf, 1, *upg_size, upg_file);
	if (result != *upg_size) {
		printf("Error: cannot read enough bytes from upg file !\n");
		return -1;
	}
	
	header = (upg_header*) *upg_buf;
	
	if(strncmp(header->magic, upg_header_magic, strlen(upg_header_magic))) {
		printf("Error: wrong magic value in header!\n");
		return -1;
	}
	
	upg_header_extra_size = header->header_size - sizeof(upg_header);
	if (upg_header_extra_size < 0) {
		printf("Error: header size field is too low !\n");
		return -1;
	} else if (upg_header_extra_size > 0) {
		printf("Warning : ignoring extra header fields (%d bytes)!\n", upg_header_extra_size);
	}
	
	if(header->header_size + header->data_size > *upg_size){
		printf("Error: size field in header larger than real file size!\n");
		return -1;
	}
	
	return 0;
}

//from http://www.linuxquestions.org/questions/linux-newbie-8/how-to-simulate-mkdir-p-home-blah1-blah2-blah3-in-c-where-only-home-exist-759487/
int mkdirp(char *pathname)
{
	char	pathname2[PATH_MAX+1];
	int	i;

	if (strlen(pathname) > PATH_MAX)
		return 1;
	else {
		for (i = 0; i <= strlen(pathname); i++)
			if (pathname[i] == '/' || pathname[i] == '\0') {
				strncpy(pathname2, pathname, i);
				pathname2[i] = '\0';
				mkdir(pathname2, S_IRWXU | S_IRWXG);
			}
		return 0;
	}
}

int unpack_upg(unsigned char *data, size_t data_size){
	FILE *upg_entry_file;
	char *dirc, *dname;
	upg_entry_header *entry;
	char dest_file[1024];
	unsigned long int offset = 0;
	unsigned int upg_entry_cnt = 0;
	size_t result;
	
	do {
		if(data_size < offset + sizeof(upg_entry_header)) {
			printf("Error: cannot read enough bytes from upg file to create entry struct!\n");
			return -1;
		}
		entry = (upg_entry_header*) &data[offset];
		
	
		if(entry->iHeaderSize < sizeof(upg_entry_header)){
			printf("Error: entry header size is not standard !\n");
			return -1;
		}else if(entry->iHeaderSize > sizeof(upg_entry_header)){
			printf("Warning: skipping extra header...\n");
		}
		offset += entry->iHeaderSize;
		
		printf("UPG entry %d : %s\n", upg_entry_cnt, entry->filename);
		printf("iAttributes:0x%08x iHeaderSize:%u iRealSize:%u iStoredSize:%u\n", entry->iAttributes, entry->iHeaderSize, entry->iRealSize, entry->iStoredSize);
		
		if(data_size < offset + entry->iStoredSize) {
			printf("Error: cannot read enough bytes from upg file to read entry data!\n");
			return -1;
		}
		
		strcpy(dest_file, "./");
		strncat(dest_file, entry->filename, sizeof(dest_file) - strlen(dest_file) - 1);
		dirc = strdup(dest_file);
		dname = dirname(dirc);
		if(dname[0] != 0x2E || dname[1])
			mkdirp(dname);
		if(dirc)
			free(dirc);
		
		upg_entry_file = fopen(dest_file, "wb");
		if(!upg_entry_file) {
			printf("Error opening upg entry file (%s)!\n", dest_file);
			break;
		}
		
		result = fwrite (&data[offset], 1, entry->iRealSize, upg_entry_file);
		if(result != entry->iRealSize)
			printf("Warning : upg entry file has not been fully written!\n");
		
		fclose(upg_entry_file);
		upg_entry_cnt++;
		offset += entry->iStoredSize;
		printf("\n");
	}while(offset < data_size);
	
	return 0;
}

int main(int argc, char* argv[])
{
	unsigned long int upg_file_size;
	unsigned int pubkey_idx = -1;
	unsigned char *upg_buf = NULL;
	upg_header *header;
	
	if(argc < 2){
		int i;
		printf("Usage: %s <upg_filename> [key_name]\n", argv[0]);
		printf("%u keys available :\n", PUBLIC_KEYS_CNT);
		for(i = 0; i < PUBLIC_KEYS_CNT; i++)
			printf("* %s\n", public_keys[i][0]);
		return -1;
	}
	
	if(read_upg(argv[1], &upg_buf, &upg_file_size)){
		printf("Error: cannot read upg file !\n");
		return -1;
	}
	header = (upg_header*) upg_buf;
	
	printf("UPG release : %s\n", header->releaseStr);
	printf("UPG description : %s\n", header->description);
	printf("UPG header size : %d\n", header->header_size);
	printf("UPG data size : %d\n", header->data_size);
	printf("UPG mask : 0x%8x\n", header->mask);
	
	if(header->mask & UPG_HEADER_FLAG_ENCRYPTION){
		if(argc != 3){
			printf("Error: this UPG seems to be encrypted. You have to provide a key name !\n");
			return -1;
		}
		
		for(pubkey_idx = 0; pubkey_idx < PUBLIC_KEYS_CNT; pubkey_idx++){
			if(!strncmp(argv[2], public_keys[pubkey_idx][0], strlen(public_keys[pubkey_idx][0])))
				break;
		}
		if(pubkey_idx == PUBLIC_KEYS_CNT){
			printf("Error: cannot find specified key !\n");
			return -1;
		}
		
		if(decrypt_upg_signature((unsigned char*)&header->signature, sizeof(header->signature), pubkey_idx)){
			printf("Error: cannot decrypt signature !\n");
			return -1;
		}
		
		printf("SHA1: ");
		printArray(header->signature.sha1, sizeof(header->signature.sha1));
		printf("AES-256 key: ");
		printArray(header->signature.aes_key, sizeof(header->signature.aes_key));
		
		if(decrypt_upg_data(&upg_buf[header->header_size], upg_file_size - header->header_size, header->signature.aes_key, sizeof(header->signature.aes_key))){
			printf("Error: cannot decrypt upg data !\n");
			return -1;
		}
	}
	
	if(unpack_upg(&upg_buf[header->header_size], header->data_size)){
		printf("Error: cannot unpack upg data !\n");
		return -1;
	}
	
	if(upg_buf)
		free(upg_buf);
	return 0;
}
