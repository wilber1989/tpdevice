#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <cjson/cJSON.h>
#include <mqtt.h>
#include "templates/posix_sockets.h"

const char * deviceID;//获取shell当中的环境变量设备ID
char rev_msg[512]={0};//获取订阅消息变量
char tmpTopic[50] = {0};//拼接各个主题
int sockfd = -1;//socket句柄

char* dpath = NULL;//项目文件路径
char* tmpath = NULL;//拼接各类路径
char* cut = NULL;//裁剪拼接字符串

struct mqtt_client client;
pthread_t client_daemon;

#define DPATH 
/*创建ecc key文件*/
int createKey()
{
    EC_KEY *eckey;
    EC_GROUP *group;
    unsigned int ret;
    EC_builtin_curve *curves;
    int crv_len;

    /* 构造 EC_KEY 数据结构 */
    eckey = EC_KEY_new();
    if(eckey == NULL)
    {
        printf("EC_KEY_new err!\n");
        return -1;
    }

    /* 获取实现的椭圆曲线个数 */
    crv_len = EC_get_builtin_curves(NULL, 0);
    curves = (EC_builtin_curve *)malloc(sizeof(EC_builtin_curve) * crv_len);
    /* 获取椭圆曲线列表 */
    EC_get_builtin_curves(curves, crv_len);

    /* 选取一种椭圆曲线 nid=curves[0].nid;会有错误，原因是密钥太短*/
    //nid = curves[415].nid;

    /* 根据选择的椭圆曲线生成密钥参数 group */
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);// X9.62/SECG curve over a 256 bit prime field（NID: 415）
    if(group==NULL)
    {
        printf("EC_GROUP_new_by_curve_name err!\n");
        return -1;
    }

    /* 设置密钥参数 */
    ret=EC_KEY_set_group(eckey,group);
    if(ret!=1)
    {
        printf("EC_KEY_set_group err.\n");
        return -1;
    }
    /* 设置密钥flag，很重要～！ */
    EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

    /* 生成密钥 */
    ret=EC_KEY_generate_key(eckey);
    if(ret!=1)
    {
        printf("EC_KEY_generate_key err.\n");
        return -1;
    }

    /* 检查密钥 */
    ret=EC_KEY_check_key(eckey);
    if(ret!=1)
    {
        printf("check eckey err.\n");
        return -1;
    }
    /* 生成公私钥 */
    FILE *pub_file,*pri_file;
    strcat(tmpath,"/key/deccpubkey.pem");
    pub_file= fopen(tmpath,"w");
        if (NULL == pub_file)
    {
        printf("create file 'pubkey' failed!\n");
        return -1;
    }
    cut=strstr(tmpath,"/key/deccpubkey.pem");
    *cut='\0';
    //EC_KEY_print_fp(stdout, pubkey, 0);
    PEM_write_EC_PUBKEY(pub_file,eckey);
    fclose(pub_file);

    strcat(tmpath,"/key/deccprikey.pem");
    pri_file= fopen(tmpath,"w");
        if (NULL == pri_file)
    {
        printf("create file 'prikey' failed!\n");
        return -1;
    }
    cut=strstr(tmpath,"/key/deccprikey.pem");
    *cut='\0';
    PEM_write_ECPrivateKey(pri_file,eckey,NULL,NULL,0,NULL,NULL);
    fclose(pri_file);
    EC_KEY_free(eckey);
    free(curves);
    return 0;
}

/*读取key文件并打印*/
int KeyPrint(const char * addr)
{
    FILE *file;
    char buffer[512];
    memset(buffer,0,512);
    file = fopen(addr, "r");
    if (NULL == file)
    {
        printf("open file 'key.pem' failed!\n");
        return  -1;
    }
    fseek(file, 0, SEEK_END);
    int length = ftell(file);
    fseek(file, 0, SEEK_SET);
    fread(buffer, sizeof(char), length, file);
    printf("%s\n\n", buffer);
    fclose(file);
    file=NULL;
    return 0;
}

/*读取密钥*/
EC_KEY* getPubKey(EC_KEY* key, const char * addr,EC_KEY * (*keyfun)() )
{
    FILE *file;
    file = fopen(addr, "r");
    if (NULL == file)
    {
        printf("open file 'pubkey' failed!\n");
        return (EC_KEY*)-1;
    }  
    (*keyfun)(file,&key);
    //RSA_print_fp(stdout,key,5);
    fclose(file);
    file=NULL;  
    return key;     
}
/*读取密钥*/
EC_KEY* getPriKey(EC_KEY* key, const char * addr,EC_KEY * (*keyfun)() )
{
    FILE *file;
    file = fopen(addr, "r");
    if (NULL == file)
    {
        printf("open file 'prikey' failed!\n");
        return (EC_KEY*)-1;
    }
    (*keyfun)(file,&key,NULL,NULL,0,NULL,NULL);  
    //RSA_print_fp(stdout,key,5);
    fclose(file);
    file=NULL;  
    return key;     
}

/*去掉转换以后的\n\t及空格*/
char* stringStrip(char *str)
{
    unsigned int i=0,j=0;
    while(str[i] != '\0')
    {
        if(str[i] != '\n'&&str[i] != '\t'&&str[i] != ' ')
        {
            str[j++] = str[i];     
        }
        i++; //源一直移动
    }
    str[j] = '\0';
    return str;
}

/*结束关闭socket*/
void exit_example(int status, int sockfd, pthread_t *client_daemon)
{
    memset(tmpTopic,0,sizeof(tmpTopic)); 
    snprintf(tmpTopic,sizeof(tmpTopic),"%s%s%s","devices/",deviceID,"/status"); 
    mqtt_publish(&client, tmpTopic, "offline", 
                 strlen("offline"), MQTT_PUBLISH_QOS_1| MQTT_PUBLISH_RETAIN); 
    mqtt_disconnect(&client);
    usleep(2000000U);
    printf("\033[1m\033[45;33m设备连接已断开！\033[0m\n\n");
    if (sockfd != -1) close(sockfd);
    if (client_daemon != NULL) pthread_cancel(*client_daemon);
    exit(status);
}

/*0.1秒同步一次客户端便于接受数据*/
void* client_refresher(void* client)
{
    while(1) 
    {
        mqtt_sync((struct mqtt_client*) client);
        usleep(100000U);
    }
    return NULL;
}
/*客户端回调函数，用于发布消息回调，订阅消息接收*/
void publish_callback(void** unused, struct mqtt_response_publish *published) 
{
    /* note that published->topic_name is NOT null-terminated (here we'll change it to a c-string) */
    char* topic_name = (char*) malloc(published->topic_name_size + 1);
    memcpy(topic_name, published->topic_name, published->topic_name_size);
    topic_name[published->topic_name_size] = '\0';
    //usleep(2000000U);
    //printf("\033[1m\033[45;32m主题('%s')最新消息:\n %s\033[0m\n", topic_name, (const char*) published->application_message);
    strcpy(rev_msg,(const char*) published->application_message);
    free(topic_name);
}

/*判断执行时间，超时未受到消息结束*/     
int setTimeout(float time,char* pubmsg)
{     
    float time_use=0;
    struct timeval start;   
    struct timeval end;
    gettimeofday(&start,NULL);  
 
    while(1)
    {
    if(rev_msg[0]!=0 && strcmp(rev_msg,pubmsg)!=0) break;//消息体判空和防止未接收新消息重复判断  
    //if(rev_msg[0]!=0 ) break;//测试用        
    gettimeofday(&end,NULL);  
    time_use=(end.tv_sec-start.tv_sec)*1000000+(end.tv_usec-start.tv_usec);//微秒         
    if(time_use>=time)       
        {           
            printf("\033[1m\033[45;33m 等待超时......\033[0m\n\n");
            return -1;        
        }
    }
    return 0;
}

/*计算消息SHA1值*/
void hashMessage(unsigned char* digest,char* message)
{   
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, message, strlen(message));
    SHA256_Final(digest, &ctx);
}

/*将普通字符串转化为16进制字符串*/ 
void charToHexStr(unsigned char* CharStr,int CharStrLen,unsigned char* hexStr)
{
    char tmp[1024];
    memset(tmp,0,1024);
    for (int i = 0; i < CharStrLen; i++)
    sprintf(&tmp[i*2],"%02x",(unsigned int)CharStr[i]);
    memcpy(hexStr,tmp,strlen(tmp));
}

/*将16进制字符串转化为普通字符串*/ 
int hexStrToChar(unsigned char* hexStr,unsigned int hexStrLen,unsigned char* CharStr)
{
    unsigned int len = hexStrLen;
    unsigned int hexStrInt[1024]={0};
    for (unsigned int i = 0; i<len; i++)
    {
        if(hexStr[i]>='0'&&hexStr[i]<='9')  
            hexStrInt[i] = (unsigned int)(hexStr[i]-'0');       
        else if(hexStr[i]>='a'&&hexStr[i]<='f')  
            hexStrInt[i] = (unsigned int)(hexStr[i]-'a'+10);      
        else if(hexStr[i]>='A'&&hexStr[i]<='F')  
            hexStrInt[i] = (unsigned int)(hexStr[i]-'A'+10);        
        else 
            {
            printf("received msg error!\n");
            exit_example(EXIT_SUCCESS, sockfd, &client_daemon);
            return -1;
            }
    }
   for (unsigned int i = 0; i < len/2; i++)
       CharStr[i]=hexStrInt[2*i]*16 + hexStrInt[2*i+1]; 
   return 0;
}

int regist(const char* topic)
{
    printf("\033[1m\033[45;33m-------------------------------------------\033[0m\n\n");
    printf("               \033[1m\033[45;33m设备认证流程\033[0m              \n\n");
    printf("\033[1m\033[45;33m-------------------------------------------\033[0m\n\n");
    usleep(2000000U);
        
    printf("\033[1m\033[45;33m[1] 创建设备密钥对,展示设备公钥:\033[0m\n\n");
    usleep(2000000U);
    //createKey();
    strcat(tmpath,"/key/deccpubkey.pem");
    KeyPrint(tmpath);
    cut=strstr(tmpath,"/key/deccpubkey.pem");
    *cut='\0';
    usleep(2000000U);

    /*读取产品私钥*/
    EC_KEY *ppri = EC_KEY_new();
    strcat(tmpath,"/key/peccprikey.pem");
    ppri = getPriKey(ppri,tmpath,PEM_read_ECPrivateKey);
    cut=strstr(tmpath,"/key/peccprikey.pem");
    *cut='\0';

    /*读取设备公钥*/
    FILE *dpubfile;
    char dpubbuf[512];
    memset(dpubbuf,0,512);
    strcat(tmpath,"/key/deccpubkey.pem");
    dpubfile = fopen(tmpath, "r");
    if (NULL == dpubfile)
    {
        printf("open file 'dpubkey.pem' failed!\n");
        return  -1;
    }
    cut=strstr(tmpath,"/key/deccpubkey.pem");
    *cut='\0';
    fseek(dpubfile, 0, SEEK_END);
    int duplength = ftell(dpubfile);
    fseek(dpubfile, 0, SEEK_SET);
    fread(dpubbuf, sizeof(char), duplength, dpubfile);
    fclose(dpubfile);

    /*创建json并摘要*/
    cJSON *root;   
    root=cJSON_CreateObject();
    cJSON_AddStringToObject(root,"flag","register");
    cJSON_AddStringToObject(root,"deviceid",deviceID); 
    cJSON_AddStringToObject(root,"pub",dpubbuf);

    char* json1 = cJSON_Print(root);  
    json1 = stringStrip(json1);//删除空格和换行
    unsigned char digest_send1[SHA256_DIGEST_LENGTH];
    hashMessage(digest_send1,json1);
    //for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
    //printf("%02x ",digest_send1[i]);

    /*对设备ID及设备公钥签名*/
    //unsigned char* cipper = NULL;
    unsigned char cipper[512];
    unsigned int signlen;
    memset(cipper,0,512);
    //signlen = ECDSA_size(ppri);
    //cipper = OPENSSL_malloc(signlen);
    int ret=ECDSA_sign(0,digest_send1,SHA256_DIGEST_LENGTH,cipper,&signlen,ppri);
    if(ret!=1)
    {
        printf("sign err!\n");
        return -1;
    }
    EC_KEY_free(ppri);//删除私钥结构体

    char shString[512*2+1];
    memset(shString, 0, 1025);
    charToHexStr(cipper,signlen,(unsigned char *)shString);
    cJSON_AddStringToObject(root,"sign",shString);
    char* json1_1 = cJSON_Print(root);

    printf("\033[1m\033[45;33m[2] 产品私钥对设备ID及设备公钥签名sign:\033[0m\n\n");
    usleep(2000000U);
    printf("%s\n\n",shString);
    usleep(2000000U); 
   
    mqtt_publish(&client, topic, json1_1, strlen((const char *)json1_1), MQTT_PUBLISH_QOS_0);   
    if (client.error != MQTT_OK) 
    {
        fprintf(stderr, "error: %s\n", mqtt_error_str(client.error));
        exit_example(EXIT_FAILURE, sockfd, &client_daemon);
    }   

    printf("\033[1m\033[45;33m[3] 终端发布认证消息:\033[0m\n\n");
    usleep(2000000U);
    printf("%s\n\n",json1_1);
    usleep(2000000U);

    printf("\033[1m\033[45;33m[4] 订阅消息并等待响应.....\033[0m\n\n");
    usleep(2000000U);

    ret = setTimeout(10000000,json1_1);
    if(ret==-1)
    {
        cJSON_Delete(root);
        free(json1_1);
        exit_example(EXIT_SUCCESS, sockfd, &client_daemon);    
    }
    cJSON_Delete(root);
    free(json1_1);

    printf("\033[1m\033[45;33m[5] 服务器返回消息:\033[0m\n\n");
    usleep(2000000U);
    printf("rev_msg:");
    for (unsigned int i = 0; i < strlen(rev_msg); i++)
    printf("\033[1m\033[45;32m%c\033[0m", rev_msg[i]);
    printf("\n\n");
    usleep(2000000U);
    printf("\033[1m\033[45;33m[6] 返回数据校验.....\033[0m\n\n");
    usleep(2000000U);

    /*获取返回数据，验证hash，用平台公钥解密比对是否一致*/
    cJSON *root_rev; 
    root_rev = cJSON_CreateObject();
    root_rev = cJSON_Parse((const char *)rev_msg);
    char status[30];
    memset(status,0,30);
    strcpy(status,(cJSON_GetObjectItem(root_rev,"status"))->valuestring);//读取状态
    char sign_rev[256];
    memset(sign_rev,0,256);
    strcpy(sign_rev,(cJSON_GetObjectItem(root_rev,"sign"))->valuestring);//读取签名
    char sever_msg[50];
    memset(sever_msg,0,50);
    strcpy(sever_msg,(cJSON_GetObjectItem(root_rev,"msg"))->valuestring);//读取服务器返回消息
    cJSON_DeleteItemFromObject(root_rev,"sign");  
    char* veri_rev = cJSON_Print(root_rev);
    veri_rev = stringStrip(veri_rev);//删除空格和换行

    /*将签名的16进制字符串转化为普通字符串*/ 
    unsigned char sign_rev_char[128];
    memset(sign_rev_char,0,128);
    hexStrToChar((unsigned char *)sign_rev,strlen(sign_rev),sign_rev_char);  

    unsigned char digest_veri[SHA256_DIGEST_LENGTH];
    hashMessage(digest_veri,veri_rev);
    printf("返回数据摘要：");
    for(unsigned int i =0;i<SHA256_DIGEST_LENGTH;i++) 
    printf("%02x",digest_veri[i]);
    printf("\n\n");
    usleep(2000000U);

    /*读取平台公钥*/
    EC_KEY *platpub= EC_KEY_new();
    strcat(tmpath,"/key/ecc_smp_pub.pem");
    platpub = getPubKey(platpub,tmpath,PEM_read_EC_PUBKEY);
    cut=strstr(tmpath,"/key/ecc_smp_pub.pem");
    *cut='\0';      
    ret=ECDSA_verify(0, digest_veri, SHA256_DIGEST_LENGTH, sign_rev_char, strlen(sign_rev)/2, platpub);
    printf("使用平台公钥验签RSA_verify ret=%d\n\n",ret);
    EC_KEY_free(platpub);
    usleep(2000000U);

    if(ret==1)
        {
            printf("\033[1m\033[45;33m[7] 返回数据验签成功 Verify_Success!\033[0m\n\n");
            usleep(2000000U);
            if (strcmp(status,"success")==0)
                printf("\033[1m\033[45;33m[8] 设备注册认证成功 Regist_Success!\n    sever_msg:%s\033[0m\n\n",sever_msg);   
            else
            {
                printf("\033[1m\033[45;33m[8] 设备注册认证失败 Regist_failed!\n    sever_msg:%s\033[0m\n\n",sever_msg);
                exit_example(EXIT_SUCCESS, sockfd, &client_daemon);
                return 0;
            } 
        }  
    else
        {
            printf("\033[1m\033[45;33m[7] 返回数据验签失败 Verify_Failed!\n    sever_msg:%s\033[0m\n\n",sever_msg);
            exit_example(EXIT_SUCCESS, sockfd, &client_daemon); 
            return 0;
        }
    rev_msg[0]=0;//清空全局标志位
    return 0;
}
int measure(const char* topic)
{
    usleep(2000000U);
    printf("\033[1m\033[45;33m-------------------------------------------\033[0m\n\n");
    printf("               \033[1m\033[45;33m设备度量流程\033[0m              \n\n");
    printf("\033[1m\033[45;33m-------------------------------------------\033[0m\n\n");
    usleep(2000000U); 

    FILE *fp1,*fp2;
    char buff_img1[1024];
    memset(buff_img1,0,1024);
    char buff_img2[1024];
    memset(buff_img2,0,1024);
        /* INPUT bios_image*/
        strcat(tmpath,"/img/bios.img");
        fp1=fopen(tmpath,"rb");
        if(fp1==NULL)
        {
            printf("Can't open file\n");
            return 0;
        }
        fread(buff_img1,1,1024,fp1);
        fclose(fp1);
        cut=strstr(tmpath,"/img/bios.img");
        *cut='\0';
        fp1=NULL;
        printf("\033[1m\033[45;33m[1] 读取bios镜像文件 from：\033[0m\n\n/tpdevice/key/bios.img\n\n");
        usleep(2000000U);

        /* SHA bios_image*/
        unsigned char dig_img1[SHA256_DIGEST_LENGTH]={0};
        hashMessage(dig_img1,buff_img1);
        char digHex_img1[SHA256_DIGEST_LENGTH*2+1]={0};
        charToHexStr(dig_img1,SHA256_DIGEST_LENGTH,(unsigned char *)digHex_img1);
        printf("\033[1m\033[45;33m[2] 计算bios镜像度量SHA值：\033[0m\n\n%s\n\n",digHex_img1);
        usleep(2000000U);

        /* INPUT os_image*/
        strcat(tmpath,"/img/os.img");
        fp2=fopen(tmpath,"rb");
        if(fp2==NULL)
        {
            printf("Can't open file\n");
            return 0;
        }
        fread(buff_img2,1,1024,fp2);
        fclose(fp2);
        cut=strstr(tmpath,"/img/os.img");
        *cut='\0';
        fp2=NULL;
        printf("\033[1m\033[45;33m[3] 读取os镜像文件 from：\033[0m\n\n/tpdevice/key/os.img\n\n");
        usleep(2000000U);

        /* SHA os_image*/
        unsigned char dig_img2[SHA256_DIGEST_LENGTH]={0};
        hashMessage(dig_img2,buff_img2);
        char digHex_img2[SHA256_DIGEST_LENGTH*2+1]={0};
        charToHexStr(dig_img2,SHA256_DIGEST_LENGTH,(unsigned char *)digHex_img2);
        printf("\033[1m\033[45;33m[4] 计算os镜像度量SHA值：\033[0m\n\n%s\n\n",digHex_img2);
        usleep(2000000U);

        /*拼接两个16进制的摘要*/
        unsigned char dig_comb[SHA256_DIGEST_LENGTH]={0};
        unsigned char tmp_comb[SHA256_DIGEST_LENGTH*4]={0};
        strcat((char *)tmp_comb,(const char *)digHex_img1);
        strcat((char *)tmp_comb,(const char *)digHex_img2);

        hashMessage(dig_comb,(char *)tmp_comb);
        char digHex_comb[SHA256_DIGEST_LENGTH*2+1];
        charToHexStr(dig_comb,SHA256_DIGEST_LENGTH,(unsigned char *)digHex_comb);
        printf("\033[1m\033[45;33m[5] 计算bios及os镜像有序度量SHA值：\033[0m\n\n%s\n\n",digHex_comb);
        usleep(2000000U);
        
        /*create publish json data*/
        cJSON *root,*ml,*pcrs,*file1,*file2;   
        root=cJSON_CreateObject();        
        cJSON_AddStringToObject(root,"flag","measure");
        cJSON_AddStringToObject(root,"deviceid",deviceID); 
        cJSON_AddItemToObject(root, "ML", ml=cJSON_CreateObject()); 

        cJSON_AddNumberToObject(ml,"length",2);
        cJSON_AddItemToObject(ml, "1", file1=cJSON_CreateObject()); 
        cJSON_AddItemToObject(ml, "2", file2=cJSON_CreateObject());

        cJSON_AddStringToObject(file1,"name","BIOS");
        cJSON_AddStringToObject(file1,"sha256",digHex_img1);
        cJSON_AddNumberToObject(file1,"PCR",1);

        cJSON_AddStringToObject(file2,"name","OS");
        cJSON_AddStringToObject(file2,"sha256",digHex_img2);
        cJSON_AddNumberToObject(file2,"PCR", 1);

        cJSON_AddItemToObject(root, "PCRs", pcrs=cJSON_CreateObject());
        cJSON_AddStringToObject(pcrs,"1",digHex_comb);
        char* out1=cJSON_Print(root);
        
        out1 = stringStrip(out1);//删除空格和换行

        unsigned char dig_json[SHA256_DIGEST_LENGTH];
        hashMessage(dig_json,out1);

        /*读取设备私钥*/
        EC_KEY *dpri= EC_KEY_new();
        strcat(tmpath,"/key/deccprikey.pem");
        dpri = getPriKey(dpri,tmpath,PEM_read_ECPrivateKey);
        cut=strstr(tmpath,"/key/deccprikey.pem");
        *cut='\0';

        /*加密度量json摘要*/
        unsigned char dig_encrypt[512]={0};
        unsigned int encryptlen;
   
        int ret=ECDSA_sign(0,dig_json,SHA256_DIGEST_LENGTH,dig_encrypt,&encryptlen,dpri);
        if(ret!=1)
        {
            printf("sign err!\n");
            return -1;
        }
        EC_KEY_free(dpri);//删除私钥结构体

        char digHex_encrypt[512*2+1];
        charToHexStr(dig_encrypt,encryptlen,(unsigned char *)digHex_encrypt);
        cJSON_AddStringToObject(root,"sign",digHex_encrypt); 
        char* meas_out = cJSON_Print(root);
               
        printf("\033[1m\033[45;33m[6] 设备发布度量消息:\033[0m\n\n");
        usleep(2000000U);
        printf("%s\n\n",meas_out);          
        mqtt_publish(&client, topic, meas_out, strlen((const char *)meas_out), MQTT_PUBLISH_QOS_0);
        if (client.error != MQTT_OK) {
            fprintf(stderr, "error: %s\n", mqtt_error_str(client.error));
            exit_example(EXIT_FAILURE, sockfd, &client_daemon);
        }  
        
        printf("\033[1m\033[45;33m[7] 订阅消息并等待响应.....\033[0m\n\n");
        usleep(2000000U);
        ret = setTimeout(10000000,meas_out);
        if(ret==-1)
        {
            cJSON_Delete(root);
            free(meas_out);
            exit_example(EXIT_SUCCESS, sockfd, &client_daemon);
        }      
        cJSON_Delete(root);
        free(meas_out);

        printf("\033[1m\033[45;33m[8] 服务器返回消息:\033[0m\n\n");
        usleep(2000000U);
        printf("rev_msg:");
        for (unsigned int i = 0; i < strlen(rev_msg); i++)
        printf("\033[1m\033[45;32m%c\033[0m", rev_msg[i]);
        printf("\n\n");
        usleep(2000000U);
        printf("\033[1m\033[45;33m[9] 返回数据校验.....\033[0m\n\n");
        usleep(2000000U);

        /*获取返回数据，验证hash，用平台公钥解密比对是否一致*/
        cJSON *root_rev; 
        root_rev = cJSON_CreateObject();
        root_rev = cJSON_Parse((const char *)rev_msg);
        char status[50];
        strcpy(status,(cJSON_GetObjectItem(root_rev,"status"))->valuestring);//读取状态值
        char sign_rev[257];
        memset(sign_rev,0,257);
        strcpy(sign_rev,(cJSON_GetObjectItem(root_rev,"sign"))->valuestring);//读取签名
        char sever_msg[100];
        strcpy(sever_msg,(cJSON_GetObjectItem(root_rev,"msg"))->valuestring);//读取服务器返回消息
        cJSON_DeleteItemFromObject(root_rev,"sign");  
        char* veri_rev = cJSON_Print(root_rev);
        veri_rev = stringStrip(veri_rev);//删除空格和换行

        /*将签名的16进制字符串转化为普通字符串*/
        unsigned char sign_rev_char[128];
        memset(sign_rev_char,0,128);
        hexStrToChar((unsigned char *)sign_rev,strlen(sign_rev),sign_rev_char); 

        unsigned char digest_veri[SHA256_DIGEST_LENGTH];
        hashMessage(digest_veri,veri_rev);
        printf("返回数据摘要：");
        for(unsigned int i =0;i<SHA256_DIGEST_LENGTH;i++) 
        printf("%02x",digest_veri[i]);
        printf("\n\n");
        usleep(2000000U);

        /*读取平台公钥*/
        EC_KEY *platpub= EC_KEY_new();
        strcat(tmpath,"/key/ecc_smp_pub.pem");
        platpub = getPubKey(platpub,tmpath,PEM_read_EC_PUBKEY);
        cut=strstr(tmpath,"/key/ecc_smp_pub.pem");
        *cut='\0';

        ret=ECDSA_verify(0, digest_veri, SHA256_DIGEST_LENGTH, sign_rev_char, strlen(sign_rev)/2, platpub);
        printf("使用平台公钥验签RSA_verify ret=%d\n\n",ret);
        EC_KEY_free(platpub);
        usleep(2000000U);
        if(ret==1)
            {
                printf("\033[1m\033[45;33m[10] 返回数据验签成功 Verify_Success!\033[0m\n\n");
                usleep(2000000U);
                if (strcmp(status,"trust")==0)
                    printf("\033[1m\033[45;33m[11] 设备可信度量验证通过 Measure_Success!\n    sever_msg:%s\033[0m\n\n",sever_msg);   
                else if(strcmp(status,"danger")==0)
                {
                    printf("\033[1m\033[45;33m[11] 设备可信度量验证不通过 Measure_Failed!\n    sever_msg:%s\033[0m\n\n",sever_msg);
                    exit_example(EXIT_SUCCESS, sockfd, &client_daemon);
                    return 0;
                }
                 else if(strcmp(status,"verify_fail")==0)
                {
                    printf("\033[1m\033[45;33m[11] 服务器端验签不通过 Server_Verify_Failed!\n    sever_msg:%s\033[0m\n\n",sever_msg);
                    exit_example(EXIT_SUCCESS, sockfd, &client_daemon);
                    return 0;
                }
                else 
                {
                    printf("\033[1m\033[45;33m[11] 度量状态无法识别 MeasureState_Unidentified!\n    sever_msg:%s\033[0m\n\n",sever_msg);              
                    exit_example(EXIT_SUCCESS, sockfd, &client_daemon);
                    return 0;
                }

            }  
        else
            {
                printf("\033[1m\033[45;33m[10]返回数据验签失败 Verify_Failed!\033[0m\n\n");
                exit_example(EXIT_SUCCESS, sockfd, &client_daemon); 
                return 0;
            } 
    rev_msg[0]=0;//清空全局标志位
    return 0;
}

int main(int argc, const char *argv[]) 
{
    const char* addr;
    const char* port;
    /* get address (argv[1] if present) */
    if (argc > 1) {
        addr = argv[1];
    } else {
        //addr = "218.89.239.8";
        addr = "127.0.0.1";
        //addr = "192.168.31.246";
        //addr = "192.168.31.183";
        //addr = "47.112.10.111";
    }
    /* get port number (argv[2] if present) */
    if (argc > 2) {
        port = argv[2];
    } else {
        port = "1883";
    }

    printf("----------------------------------------\n");
    printf("\033[1m\033[45;33m终端设备认证、度量演示程序\033[0m\n");
    printf("----------------------------------------\n");
    printf("\033[1m\033[45;33mPress ENTER to start.\033[0m\n");
    printf("----------------------------------------\n");
    printf("\033[1m\033[45;33mPress CTRL+D to exit.\033[0m\n");
    printf("----------------------------------------\n");
    
    while(fgetc(stdin)!= '\n');
    dpath = getenv("DPATH");
    //printf("dpath:%s\n",dpath ); 
    tmpath= dpath;
    deviceID = getenv("DEVICEID");
    //createKey();//创建密钥时用
    sockfd = open_nb_socket(addr, port);
    if (sockfd == -1) {
        perror("Failed to open socket: ");
        exit_example(EXIT_FAILURE, sockfd, NULL);
    }
    fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK);

    /*建立mqtt客户端*/
    uint8_t sendbuf[2048]; 
    uint8_t recvbuf[1024]; 
    mqtt_init(&client, sockfd, sendbuf, sizeof(sendbuf), recvbuf, sizeof(recvbuf), publish_callback); 
    
    snprintf(tmpTopic,sizeof(tmpTopic),"%s%s%s","devices/",deviceID,"/status");
    mqtt_connect(&client, deviceID, tmpTopic, "exception", 
                strlen("exception"), NULL, NULL, MQTT_PUBLISH_QOS_1| MQTT_CONNECT_WILL_RETAIN, 400);
    if (client.error != MQTT_OK) 
    {
        fprintf(stderr, "error: %s\n", mqtt_error_str(client.error));
        exit_example(EXIT_FAILURE, sockfd, NULL);
    }

    if(pthread_create(&client_daemon, NULL, client_refresher, &client))
    {
        fprintf(stderr, "Failed to start client daemon.\n");
        exit_example(EXIT_FAILURE, sockfd, NULL);

    }
    memset(tmpTopic,0,sizeof(tmpTopic));
    snprintf(tmpTopic,sizeof(tmpTopic),"%s%s%s","devices/",deviceID,"/status"); 
    mqtt_publish(&client, tmpTopic, "online", 
                 strlen("online"), MQTT_PUBLISH_QOS_1| MQTT_PUBLISH_RETAIN);
    
    memset(tmpTopic,0,sizeof(tmpTopic));
    snprintf(tmpTopic,sizeof(tmpTopic),"%s%s%s","devices/",deviceID,"/regist/res"); 
    mqtt_subscribe(&client, tmpTopic, 0);
    
    memset(tmpTopic,0,sizeof(tmpTopic)); 
    snprintf(tmpTopic,sizeof(tmpTopic),"%s%s%s","devices/",deviceID,"/measure/res"); 
    mqtt_subscribe(&client, tmpTopic, 0);

    /*设备认证流程*/
    memset(tmpTopic,0,sizeof(tmpTopic));
    snprintf(tmpTopic,sizeof(tmpTopic),"%s%s%s","devices/",deviceID,"/regist"); 
    regist(tmpTopic);

    /*设备度量流程*/
    memset(tmpTopic,0,sizeof(tmpTopic));
    snprintf(tmpTopic,sizeof(tmpTopic),"%s%s%s","devices/",deviceID,"/measure"); 
    measure(tmpTopic); 
     
    while(fgetc(stdin)!=EOF);
    exit_example(EXIT_SUCCESS, sockfd, NULL);
    return 0;
}