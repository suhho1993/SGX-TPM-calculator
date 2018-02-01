/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


// App.cpp : Defines the entry point for the console application.
#include <stdio.h>
#include <map>
#include "../Enclave1/Enclave1_u.h"
#include "../Enclave2/Enclave2_u.h"
#include "../Enclave3/Enclave3_u.h"
#include "sgx_eid.h"
#include "sgx_urts.h"
#define __STDC_FORMAT_MACROS
#include <inttypes.h>


#define UNUSED(val) (void)(val)
#define TCHAR   char
#define _TCHAR  char
#define _T(str) str
#define scanf_s scanf
#define _tmain  main

extern std::map<sgx_enclave_id_t, uint32_t>g_enclave_id_map;


sgx_enclave_id_t e1_enclave_id = 0;
sgx_enclave_id_t e2_enclave_id = 0;

#define ENCLAVE1_PATH "libenclave1.so"
#define ENCLAVE2_PATH "libenclave2.so"

void waitForKeyPress()
{
    char ch;
    int temp;
    printf("\n\nHit a key....\n");
    temp = scanf_s("%c", &ch);
}

uint32_t load_enclaves()
{
    uint32_t enclave_temp_no;
    int ret, launch_token_updated;
    sgx_launch_token_t launch_token;

    enclave_temp_no = 0;

    ret = sgx_create_enclave(ENCLAVE1_PATH, SGX_DEBUG_FLAG, &launch_token, &launch_token_updated, &e1_enclave_id, NULL);
    if (ret != SGX_SUCCESS) {
                return ret;
    }

    enclave_temp_no++;
    g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(e1_enclave_id, enclave_temp_no));

    ret = sgx_create_enclave(ENCLAVE2_PATH, SGX_DEBUG_FLAG, &launch_token, &launch_token_updated, &e2_enclave_id, NULL);
    if (ret != SGX_SUCCESS) {
                return ret;
    }

    enclave_temp_no++;
    g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(e2_enclave_id, enclave_temp_no));

    return SGX_SUCCESS;
}
//TPM_Calc
#define MAX_COMMAND_LEN 150

static void sha256_print(unsigned char* in){
	int i = 0;
	char res[65]={0,};
	for(i=0; i<32; i++){
		sprintf(res+(i*2),"%02x",in[i]);
	}
	printf("\nSHA256:      %s\n",res);
	return ;
}

int TPM_calc()
{
	unsigned char golden_pcr[32];
	uint32_t re_stat;

	FILE * file;
	char * line = (char*)malloc(sizeof(char)*MAX_COMMAND_LEN);
	size_t len = MAX_COMMAND_LEN;

	file = fopen("ToMeasure.txt","r");
	if(!file)
	{
		printf("ToMeasure.txt open fail\n");
		return -1;
	}

	while(fgets(line, len, file)!= NULL)
	{
		printf( "read line :%s", line);
		
		if(!strncmp(line,"GRUB",sizeof(char)*4)){
			printf("this is Grub\n");
			FILE* grub_fp = fopen("GRUB.efi","r");
			if(!grub_fp){
				printf("fileopen fail\n");
				return -1;
			}
			size_t sizeof_FILE = 614192;
			
			void* data =NULL;
			data= malloc(sizeof_FILE);
			if(!data){	
				printf("data malloc fail\n");
				return -1;
			}
			size_t test_r=fread(data, 1, sizeof_FILE,grub_fp);
			printf("%d  %d\n",test_r, sizeof_FILE);

			Enclave1_TPM_calc_grub(e1_enclave_id, &re_stat, (unsigned char*) data, sizeof_FILE);
			if(re_stat != 0x1732)
				printf("\nTPM_CALC FAIL\n");		
			free(data);
 		fclose(grub_fp);
		}
	
		else if(!strncmp(line,"KERNEL",sizeof(char)*6)){
			printf("this is kernel\n");
			FILE* kernel_fp = fopen("KERNEL.efi","r");
			if(!kernel_fp){
				printf("fileopen fail\n");
				return -1;
			}
			size_t sizeof_FILE = 7104112;

			void* data =NULL;
			data= malloc(sizeof_FILE);
			if(!data){	
				printf("data malloc fail\n");
				return -1;
			}
			fread(data, sizeof_FILE,1,kernel_fp);
			printf("%s\n",(char*)data);
			Enclave1_TPM_calc_kernel(e1_enclave_id, &re_stat, (unsigned char *)(data), sizeof_FILE);
			if(re_stat != 0x1732)
				printf("\nTPM_CALC FAIL\n");	
			free(data);
			fclose(kernel_fp);
		}
		
		else if(!strncmp(line,"UBUNTU",sizeof(char)*6)){
			printf("this is UBUNTU\n");
			
			FILE* U_file = fopen("UBUNTU.txt","r");
			if(!U_file){
				printf("fileopen fail\n");
				return -1;
			}
			size_t sizeof_FILE =781;
			
			char* data =NULL;
			data= (char*)malloc(sizeof_FILE);
			if(!data){	
				printf("data malloc fail\n");
				return -1;
			}	
			fread(data,sizeof_FILE,1,U_file);
			size_t len = sizeof_FILE;
			data[len-1]='\0';

			printf("%s\n", data);
			Enclave1_TPM_calc_long(e1_enclave_id, &re_stat, (unsigned char*)data, sizeof_FILE);
			if(re_stat != 0x1732)
				printf("\nTPM_CALC FAIL\n");	
			free(data);
			fclose(U_file);	
		}
		else if(!strncmp(line,"MENU",sizeof(char)*4)){
			printf("this is MENU\n");
			FILE* M_file = fopen("MENUENTRY.txt","r");
			if(!M_file){
				printf("fileopen fail\n");
				return -1;
			}
			size_t sizeof_FILE =2889;
			char* data =NULL;
			data= (char*)malloc(sizeof_FILE);
			if(!data){	
				printf("data malloc fail\n");
				return -1;
			}
			fread(data,sizeof_FILE,1,M_file);
			
			size_t len = sizeof_FILE;
			data[len-1]='\0';

			printf("size:%s\n", data);
			Enclave1_TPM_calc_long(e1_enclave_id, &re_stat, (unsigned char *)data, sizeof_FILE);
			if(re_stat != 0x1732)
				printf("\nTPM_CALC FAIL\n");	
			free(data);
			fclose(M_file);
		}
		else if(!strncmp(line,"SYSTEM",sizeof(char)*5)){
			printf("this is SYSTEM\n");
			FILE* S_file = fopen("SYSTEM.txt","r");
			if(!S_file){
				printf("fileopen fail\n");
				return -1;
			}
			size_t sizeof_FILE =55;
			
			char* data =NULL;
			data= (char*)malloc(sizeof_FILE);
			if(!data){	
				printf("data malloc fail\n");
				return -1;
			}
			fread(data,sizeof_FILE,1,S_file);
			size_t len = sizeof_FILE;
			data[len-1]='\0';

			printf("%s\n", data);
			Enclave1_TPM_calc_long(e1_enclave_id, &re_stat, (unsigned char*)data, sizeof_FILE);
			if(re_stat != 0x1732)
				printf("\nTPM_CALC FAIL\n");	

			free(data);
			fclose(S_file);
		}
		else {
			printf("this is CMD\n");//	size_t sizeof_FILE =615216;
			size_t cmd_len = strlen(line);
			cmd_len-=1;
			line[cmd_len-1]='\0';
			printf("size: %d /// %s\n", cmd_len, line);

			Enclave1_TPM_calc_cmd(e1_enclave_id, &re_stat,(unsigned char *) line, cmd_len);
			if(re_stat != 0x1732)
				printf("\nTPM_CALC FAIL\n");	

		}
	}//end of while 
	free(line);

	memset(golden_pcr,0, sizeof(golden_pcr));
	Enclave1_PCR_get(e1_enclave_id, &re_stat, golden_pcr, 32);
	if(re_stat != 0x1732)
		printf("\nPCR_GET FAIL\n");	
	
	sha256_print(golden_pcr);	
	fclose(file);
	return 0;
}

int _tmain(int argc, _TCHAR* argv[])
{
    uint32_t ret_status;
    sgx_status_t status;
    int test_ret;

    UNUSED(argc);
    UNUSED(argv);

    if(load_enclaves() != SGX_SUCCESS)
    {
        printf("\nLoad Enclave Failure");
    }

    printf("\nAvailable Enclaves");
    printf("\nEnclave1 - EnclaveID %" PRIx64, e1_enclave_id);
    printf("\nEnclave2 - EnclaveID %" PRIx64, e2_enclave_id);
    
    do
    {
	    TPM_calc();
        //Test Create session between Enclave1(Source) and Enclave2(Destination)
        status = Enclave1_test_create_session(e1_enclave_id, &ret_status, e1_enclave_id, e2_enclave_id);
        if (status!=SGX_SUCCESS)
        {
            printf("Enclave1_test_create_session Ecall failed: Error code is %x", status);
            break;
        }
        else
        {
            if(ret_status==0)
            {
                printf("\n\nSecure Channel Establishment between Source (E1) and Destination (E2) Enclaves successful !!!");
            }
            else
            {
                printf("\nSession establishment and key exchange failure between Source (E1) and Destination (E2): Error code is %x", ret_status);
                break;
            }
        }

        //Test Enclave to Enclave call between Enclave1(Source) and Enclave2(Destination)
        status = Enclave1_test_enclave_to_enclave_call(e1_enclave_id, &ret_status, e1_enclave_id, e2_enclave_id);
        if (status!=SGX_SUCCESS)
        {
            printf("Enclave1_test_enclave_to_enclave_call Ecall failed: Error code is %x", status);
            break;
        }
        else
        {
            if(ret_status==0)
            {
                printf("\n\nEnclave to Enclave Call between Source (E1) and Destination (E2) Enclaves successful !!!");
            }
            else
            {
                printf("\n\nEnclave to Enclave Call failure between Source (E1) and Destination (E2): Error code is %x", ret_status);
                break;
            }
        }
        //Test message exchange between Enclave1(Source) and Enclave2(Destination)
        status = Enclave1_test_message_exchange(e1_enclave_id, &ret_status, e1_enclave_id, e2_enclave_id);
        if (status!=SGX_SUCCESS)
        {
            printf("Enclave1_test_message_exchange Ecall failed: Error code is %x", status);
            break;
        }
        else
        {
            if(ret_status==0)
            {
                printf("\n\nMessage Exchange between Source (E1) and Destination (E2) Enclaves successful !!!");
            }
            else
            {
                printf("\n\nMessage Exchange failure between Source (E1) and Destination (E2): Error code is %x", ret_status);
                break;
            }
        }

#pragma warning (push)
#pragma warning (disable : 4127)    
    }while(0);
#pragma warning (pop)

    sgx_destroy_enclave(e1_enclave_id);
    sgx_destroy_enclave(e2_enclave_id);

    waitForKeyPress();

    return 0;
}
