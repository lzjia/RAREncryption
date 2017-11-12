#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "hash_func.h"
#include <math.h>
#include <algorithm>
#include <iostream>
#include <vector>

using namespace std;
typedef unsigned char byte;
typedef unsigned int byte4;
#define NUM_THREADS 5


byte4 EncryptionFlags[4];
byte CRC[4],TitleSize[1],KDFCount[1],salt[16],PswCheck[8],checksum[4];
int C;
byte4 Salt[4];
byte4 SaltTrue[16]={0};
byte4 PswCheckTrue[2]={0};
byte4 MyPwd[10000][16]={0};
byte4 int2[8]={0x80000000,0,0,0,0,0,0,(64 + 32) * 8};
byte4 xcheck_val[2];
std::vector<int> random;

byte4 To4byte(byte *Array,int length);
void To4byte4(byte *Array,byte4 *result);
void ReadRar();
void InitPwd();
int PBKDF2(int pwdNum);
void randperm();
void EncryptedPwd();
void InitPwdCheck();
bool checkPwd();

bool checkPwd()
{
	return (xcheck_val[0]^PswCheckTrue[0])||(xcheck_val[1]^PswCheckTrue[1]);

}
void InitPwdCheck()
{
	byte temp0[4],temp1[4];
	for(int i=0;i<4;i++){
		temp0[i] = PswCheck[i];
		temp1[i] = PswCheck[i+4];
	}
	PswCheckTrue[0]=To4byte(temp0,4);
	PswCheckTrue[1]=To4byte(temp1,4);
}

void EncryptedPwd()
{
	for(int i=0;i<random.size();i++){
		printf("test: %04d LeftNum: %d\n",random[i],9999-i);
		if(PBKDF2(random[i])) return;
	}
	printf("Not Found!\n");
}

int PBKDF2(int pwdNum)
{
	byte4 temp[8],out[8];
	byte4 M[16];

	MyHmac(MyPwd[pwdNum],SaltTrue,temp);
	memcpy(out,temp,8*4);
	for(int i=1;i<C;i++){
		memcpy(M,temp,8*4);
		memcpy(M+8,int2,8*4);
		MyHmac(MyPwd[pwdNum],M,temp);
		for(int j=0;j<8;j++){
			out[j] = out[j]^temp[j];
		} 
	}
	xcheck_val[0]=out[0]^out[2]^out[4]^out[6];
	xcheck_val[1]=out[1]^out[3]^out[5]^out[7];
	if(!checkPwd()){
		printf("Find PassWord: %04u\n",pwdNum);
		return 1;
	}
	return 0;
}


void InitPwd()
{
	byte4 i;
	byte4 j=0xffffffff;
	byte array[4];
	for(i=0;i<10000;i++){
		array[0]= i/1000+'0';
		array[1]= i%1000/100+'0';
		array[2]= i%1000%100/10+'0';
		array[3]= i%10+'0';
		MyPwd[i][0]=To4byte(array,4);
	}
	for(int i=0;i<10000;i++){
		random.push_back(i);
	}
	random_shuffle(random.begin(),random.end());
}
void To4byte4(byte *Array,byte4 *result){
	byte temp0[4],temp1[4],temp2[4],temp3[4];
	for(int i=0;i<4;i++){
		temp0[i] = Array[i];
		temp1[i] = Array[i+4];
		temp2[i] = Array[i+8];
		temp3[i] = Array[i+12];
	}
	result[0]=To4byte(temp0,4);
	result[1]=To4byte(temp1,4);
	result[2]=To4byte(temp2,4);
	result[3]=To4byte(temp3,4);
}


byte4 To4byte(byte *Array,int length)
{
	byte4 Int4Byte = 0xffffffff;
	if(length==4){
	Int4Byte = Int4Byte & Array[0];
	Int4Byte = Int4Byte << 8;
	Int4Byte = Int4Byte | Array[1];
	Int4Byte = Int4Byte << 8;
	Int4Byte = Int4Byte | Array[2];
	Int4Byte = Int4Byte << 8;
	Int4Byte = Int4Byte | Array[3];
	}else if(length==1){
		Int4Byte = 0x000000ff & Array[0];
	}
	return Int4Byte;
}


void ReadRar()
{
	byte flag1[1]={'1'};
	byte flag2[1]={'1'};
	FILE* rarFile;
	char str[200];
	printf("Input: \n");
	cin.getline(str,200);
	rarFile = fopen(str,"r+b");
	while((flag1[0]!=1)||(flag2[0]!=0)){
		fread(flag1,sizeof(byte),1,rarFile);
		fread(flag2,sizeof(byte),1,rarFile);
	}
	printf("Find Encrypted message!\n");
	fread(CRC,sizeof(byte),4,rarFile);
	fread(TitleSize,sizeof(byte),1,rarFile);
	fread(EncryptionFlags,sizeof(byte),4,rarFile);
	fread(KDFCount,sizeof(byte),1,rarFile);
	fread(salt,sizeof(byte),16,rarFile);
	fread(PswCheck,sizeof(byte),8,rarFile);
	fread(checksum,sizeof(byte),4,rarFile);
	int tmp=To4byte(KDFCount,1);
	C= pow(2.0,tmp)+32;
	To4byte4(salt,Salt);
	for(byte4 i=0;i<4;i++){
		SaltTrue[i]=Salt[i];
	}
	SaltTrue[15] =0x2a0; 
	SaltTrue[5] = 0x80000000;
	SaltTrue[4]=1;
	InitPwd();
	InitPwdCheck();
}


int main(void)
{
	ReadRar();
	EncryptedPwd();
}
