/*
 OPPOENCRYPT by affggh
 希望oppo别找我麻烦...
*/

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <openssl/sha.h>

#include "tiny-AES-c/aes.h"

#define MAX_DATA_LEN 1024
#define SHA1_LENTH 20
#define ECB 1

/*
 OZIP 文件格式
 Magic OPPOENCRYPT! 0x00 0x00 0x00 0x00
 16byte file size
 40byte Sha1 checksum
 1008byte 0x00
 DATA [每隔4000（hex）加密一次 aes-128-ecb]
*/

/* 
 These Keys from oppo_ozip_decrypt on github
 There are many keys... I choose R9s
        "D6EECF0AE5ACD4E0E9FE522DE7CE381E",  # mnkey
        "D6ECCF0AE5ACD4E0E92E522DE7C1381E",  # mkey
        "D6DCCF0AD5ACD4E0292E522DB7C1381E",  # realkey, R9s CPH1607 MSM8953, Plus, R11, RMX1921 Realme XT, RMX1851EX Realme Android 10, RMX1992EX_11_OTA_1050
        "D7DCCE1AD4AFDCE2393E5161CBDC4321",  # testkey
        "D7DBCE2AD4ADDCE1393E5521CBDC4321",  # utilkey
        "D7DBCE1AD4AFDCE1393E5121CBDC4321",  # R11s CPH1719 MSM8976, Plus
        "D4D2CD61D4AFDCE13B5E01221BD14D20",  # FindX CPH1871 SDM845
        "261CC7131D7C1481294E532DB752381E",  # FindX
        "1Fxu7L83m1qDUM84fvsrQN3iwEjaxeRLEy",  # Realme 2 pro SDM660/MSM8976
        "D4D2CE11D4AFDCE13B3E0121CBD14D20",  # K1 SDM660/MSM8976
        "1C4C1EA3A12531AE491B21BB31613C11",  # Realme 3 Pro SDM710, X, 5 Pro, Q, RMX1921 Realme XT
        "1C4C1EA3A12531AE4A1B21BB31C13C21",  # Reno 10x zoom PCCM00 SDM855, CPH1921EX Reno 5G
        "1C4A11A3A12513AE441B23BB31513121",  # Reno 2 PCKM00 SDM730G
        "1C4A11A3A12589AE441A23BB31517733",  # Realme X2 SDM730G
        "1C4A11A3A22513AE541B53BB31513121",  # Realme 5 SDM665
        "2442CE821A4F352E33AE81B22BC1462E",  # R17 Pro SDM710
        "14C2CD6214CFDC2733AE81B22BC1462C",  # CPH1803 OppoA3s SDM450/MSM8953
        "1E38C1B72D522E29E0D4ACD50ACFDCD6",
        "12341EAAC4C123CE193556A1BBCC232D",
        "2143DCCB21513E39E1DCAFD41ACEDBD7",
        "2D23CCBBA1563519CE23C1C4AA1E3412",  # A77 CPH1715 MT6750T
        "172B3E14E46F3CE13E2B5121CBDC4321",  # Realme 1 MTK P60
        "ACAA1E12A71431CE4A1B21BBA1C1C6A2",  # Realme U1 RMX1831 MTK P70
        "ACAC1E13A72531AE4A1B22BB31C1CC22",  # Realme 3 RMX1825EX P70
        "1C4411A3A12533AE441B21BB31613C11",  # A1k CPH1923 MTK P22
        "1C4416A8A42717AE441523B336513121",  # Reno 3 PCRM00 MTK 1000L, CPH2059 OPPO A92, CPH2067 OPPO A72
        "55EEAA33112133AE441B23BB31513121",  # RenoAce SDM855Plus
        "ACAC1E13A12531AE4A1B21BB31C13C21",  # Reno, K3
        "ACAC1E13A72431AE4A1B22BBA1C1C6A2",  # A9
        "12CAC11211AAC3AEA2658690122C1E81",  # A1,A83t
        "1CA21E12271435AE331B81BBA7C14612",  # CPH1909 OppoA5s MT6765
        "D1DACF24351CE428A9CE32ED87323216",  # Realme1(reserved)
        "A1CC75115CAECB890E4A563CA1AC67C8",  # A73(reserved)
        "2132321EA2CA86621A11241ABA512722",  # Realme3(reserved)
        "22A21E821743E5EE33AE81B227B1462E"
        #F3 Plus CPH1613 - MSM8976
*/

void Usage();

uint8_t key[16] = {0xd6, 0xdc, 0xcf, 0x0a, 0xd5, 0xac, 0xd4, 0xe0, 0x29, 0x2e, 0x52, 0x2d, 0xb7, 0xc1, 0x38, 0x1e}; // R9s
struct AES_ctx ctx;

int main(int argc, char *argv[]) {
	if(argc<2){
		Usage();
		return 0;
	}
	FILE *fp,*fp2;
	char newfile[128],sha1[40];
	int i,size;
	strcpy(newfile, argv[1]);
	strcat(newfile, ".ozip");
	fp = fopen(argv[1],"rb");
	if(access(argv[1],0)!=0){
		fprintf(stderr, "File %s not exist... \n", argv[1]);
		return 1;
	}
	// Head
	fp2 = fopen(newfile, "wb"); // open new file
	fprintf(stdout, "Gerenating file %s...\n", newfile);
	fputs("OPPOENCRYPT!", fp2); // generate header
	for(i=0;i<4;i++){
		fputc(0x00, fp2); // 补0
	}
	// Size
	fprintf(stdout, "Get %s size...", argv[1]);
	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	//fclose(fp);
	fprintf(stdout, "%d...\n", size);
	fprintf(fp2, "%d", size);
	while(ftell(fp2)!=32){
		fputc(0x00, fp2); // 补0
	}
	// SHA1
    SHA_CTX sha1_ctx;
    //FILE *fp = NULL;
    char *strFilePath = argv[1];
    unsigned char SHA1result[SHA1_LENTH];
    char DataBuff[MAX_DATA_LEN];
    int len;
    int t = 0;
    i = 0;

    //fp = fopen(strFilePath, "rb");  //打开文件

    do
    {
        SHA1_Init(&sha1_ctx);

        while(!feof(fp))
        {
            memset(DataBuff, 0x00, sizeof(DataBuff));

            len = fread(DataBuff, 1, MAX_DATA_LEN, fp);
            if(len)
            {
                t += len;
                //printf("len = [%d] 1\n", len);
                SHA1_Update(&sha1_ctx, DataBuff, len);   //将当前文件块加入并更新SHA1
            }
        }

        //printf("len = [%d]\n", t);

        SHA1_Final(SHA1result,&sha1_ctx);       //获取SHA1

        fprintf(stdout, "Get file sha1 : ");
        for(i = 0; i<SHA1_LENTH; i++)   //将SHA1以16进制输出
        {
            fprintf(stdout, "%02x", (int)SHA1result[i]);
			fprintf(fp2, "%02x", (int)SHA1result[i]);
        }
        fprintf(stdout, "\n");

    } while(0);
	
	while(ftell(fp2)!=4176){
		fputc(0x00, fp2); // 补0
	}
	
	// Data encryption
	fprintf(stdout, "Encrypt File...\n");
	uint8_t buf[16], buf2[16384];
	AES_init_ctx(&ctx, key);
	fseek(fp, 0 , SEEK_SET);
	while(feof(fp)==0){
		fread(buf, 16, 1, fp);
		AES_ECB_encrypt(&ctx, buf);
		fwrite(buf, 16, 1, fp2);
		if(size-ftell(fp)<16384){
			int lef = size-ftell(fp);
			fread(buf2, lef, 1, fp);
			fwrite(buf2, lef, 1, fp2);
			break;
		}else{
			fread(buf2, 16384, 1, fp);
			fwrite(buf2, 16384, 1, fp2);
		}
		//fputs("Encrypt\n", stdout);
	}
	
	fclose(fp);
	fclose(fp2);
	return 0;
}
 
void Usage(){
	fprintf(stdout, "Usage:\n    zip2ozip [FILE]\n");
}
