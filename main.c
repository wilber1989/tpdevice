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

/*获取订阅消息变量*/
char rev_msg[512]={0};
int sockfd = -1;//socket句柄
char* dpath = NULL;
char* tmpath = NULL;
char* cut = NULL;//裁剪拼接字符串

#define DPATH 
/*创建pem key文件*/
int createKey()
{
    RSA *rsa= RSA_new();
    BIGNUM *bne=BN_new();
    BN_set_word(bne,RSA_F4);
    RSA_generate_key_ex(rsa,512,bne,NULL);
    RSA* pub = RSAPublicKey_dup(rsa);
    RSA* pri = RSAPrivateKey_dup(rsa);  
    FILE *pub_file,*pri_file;
    if (NULL == rsa)
    {
        printf("RSA not initial.\n");
        return 0;
    }
    //RSA_print_fp(stdout, rsa,5);
    strcat(tmpath,"key/dpubkey.key");
    pub_file = fopen(tmpath,"w");
    tmpath=strtok(tmpath,"k");
    strcat(tmpath,"key/dprikey.key");
    pri_file = fopen(tmpath,"w");
    tmpath=strtok(tmpath,"k");
    if (NULL == pub_file||NULL == pri_file)
    {
        printf("create file 'key' failed!\n");
        return 0;
    }
    PEM_write_RSAPublicKey(pub_file, pub);
    PEM_write_RSAPrivateKey(pri_file, pri, NULL, NULL, 512, NULL, NULL);
    fclose(pub_file);
    fclose(pri_file);
    RSA_free(rsa);
    return 1;
}

/*读取key文件并打印*/
int KeyPrint(const char * addr)
{
    FILE *file;
    char buffer[512];
    file = fopen(addr, "r");
    if (NULL == file)
    {
        printf("open file 'pubkey.key' failed!\n");
        return  -1;
    }
    fseek(file, 0, SEEK_END);
    int length = ftell(file);
    fseek(file, 0, SEEK_SET);
    fread(buffer, sizeof(char), length-3, file);
    printf("%s\n\n", buffer);
    fclose(file);
    file=NULL;
    return 0;
}

/*读取密钥*/
RSA* getKey(RSA* key, const char * addr,RSA* (*keyfun)() )
{
    FILE *file;
    file = fopen(addr, "r");
    if (NULL == file)
    {
        printf("open file 'key' failed!\n");
        return (RSA*)-1;
    }
    (*keyfun)(file,&key, NULL, NULL);
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
            {str[j++] = str[i];
        
        }i++; //源一直移动
    }
    str[j] = '\0';
    return str;
}

/*结束关闭socket*/
void exit_example(int status, int sockfd, pthread_t *client_daemon)
{
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
int setTimeout(float time)
{     
    float time_use=0;
    struct timeval start;   
    struct timeval end;
    gettimeofday(&start,NULL);  

    while(1)
    {
    if(rev_msg[0]!=0) break;//获得消息中断循环        
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
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, message, strlen(message));
    SHA1_Final(digest, &ctx);
}



int regist(const char* addr, const char* port, const char* topic)
{
    printf("\033[1m\033[45;33m-------------------------------------------\033[0m\n\n");
    printf("               \033[1m\033[45;33m设备认证流程\033[0m              \n\n");
    printf("\033[1m\033[45;33m-------------------------------------------\033[0m\n\n");
    usleep(2000000U);
        
    printf("\033[1m\033[45;33m[1] 创建设备密钥对,展示设备公钥:\033[0m\n\n");
    usleep(2000000U);
    //createKey();
    tmpath= dpath;
    strcat(tmpath,"/key/dpubkey.key");
    KeyPrint(tmpath);
    cut=strstr(tmpath,"/key/dpubkey.key");
    *cut='\0';
    usleep(2000000U);


    /*读取产品私钥*/
    RSA *ppri= RSA_new();
    strcat(tmpath,"/key/pprikey.key");
    ppri = getKey(ppri,tmpath,PEM_read_RSAPrivateKey);
    cut=strstr(tmpath,"/key/pprikey.key");
    *cut='\0';

    /*读取设备公钥*/
    RSA *dpub= RSA_new();
    strcat(tmpath,"/key/dpubkey.key");
    dpub = getKey(dpub,tmpath,PEM_read_RSAPublicKey);
    cut=strstr(tmpath,"/key/dpubkey.key");
    *cut='\0';
    
    /*提取设备公钥n和e*/
    BIGNUM *bne=BN_new();
    BIGNUM *bnn=BN_new();
    char *dpub_n = BN_bn2hex(dpub->n);
    char *dpub_e = BN_bn2hex(dpub->e);
    //printf("%s\n",dpub_n);
    //printf("%s\n",dpub_e);
    RSA_free(dpub);//删除公钥结构体

    /*创建json并摘要*/
    cJSON *root;   
    root=cJSON_CreateObject();
    cJSON_AddStringToObject(root,"flag","register");
    cJSON_AddStringToObject(root,"deviceid","chislab1"); 
    cJSON_AddStringToObject(root,"pub_e",dpub_e);
    cJSON_AddStringToObject(root,"pub_n",dpub_n);
    char* json1 = cJSON_Print(root);  
    json1 = stringStrip(json1);//删除空格和换行
    unsigned char digest_send1[SHA_DIGEST_LENGTH];
    hashMessage(digest_send1,json1);

    /*对设备ID及设备公钥n和e签名*/
    unsigned char cipper[512]={0};
    unsigned int signlen;
    RSA_sign(NID_sha1, (unsigned char *)digest_send1,SHA_DIGEST_LENGTH, cipper, (unsigned int *)&signlen,ppri);
    RSA_free(ppri);//删除私钥结构体

    char shString[512*2+1];
    for (unsigned int i = 0; i < signlen; i++)
    sprintf(&shString[i*2], "%02x", (unsigned int)cipper[i]);
    cJSON_AddStringToObject(root,"sign",shString);
    char* json1_1 = cJSON_Print(root);

    printf("\033[1m\033[45;33m[2] 产品私钥对设备ID及设备公钥签名sign:\033[0m\n\n");
    usleep(2000000U);
    printf("%s\n\n",shString);
    usleep(2000000U); 

    sockfd = open_nb_socket(addr, port);
    if (sockfd == -1) {
        perror("Failed to open socket: ");
        exit_example(EXIT_FAILURE, sockfd, NULL);
    }
    fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK);

    /*认证发布客户端*/
    struct mqtt_client client;
    uint8_t sendbuf[2048]; 
    uint8_t recvbuf[1024]; 
    mqtt_init(&client, sockfd, sendbuf, sizeof(sendbuf), recvbuf, sizeof(recvbuf), publish_callback);
    mqtt_connect(&client, "register_devices", NULL, NULL, 0, NULL, NULL, 0, 400);
    if (client.error != MQTT_OK) 
    {
        fprintf(stderr, "error: %s\n", mqtt_error_str(client.error));
        exit_example(EXIT_FAILURE, sockfd, NULL);
    }

    pthread_t client_daemon;
    if(pthread_create(&client_daemon, NULL, client_refresher, &client))
    {
        fprintf(stderr, "Failed to start client daemon.\n");
        exit_example(EXIT_FAILURE, sockfd, NULL);

    }

    mqtt_subscribe(&client, "devices/measurement/register/res", 0);

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

    cJSON_Delete(root);
    free(json1_1);

    printf("\033[1m\033[45;33m[4] 订阅消息并等待响应.....\033[0m\n\n");
    usleep(2000000U);
    int ret = setTimeout(10000000);
    if(ret==-1)
    exit_example(EXIT_SUCCESS, sockfd, NULL);

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
    char status[10];
    strcpy(status,(cJSON_GetObjectItem(root_rev,"status"))->valuestring);//读取状态
    char sign_rev[257];
    strcpy(sign_rev,(cJSON_GetObjectItem(root_rev,"sign"))->valuestring);//读取签名
    char sever_msg[30];
    strcpy(sever_msg,(cJSON_GetObjectItem(root_rev,"msg"))->valuestring);//读取服务器返回消息
    cJSON_DeleteItemFromObject(root_rev,"sign");  
    char* veri_rev = cJSON_Print(root_rev);

    veri_rev = stringStrip(veri_rev);//删除空格和换行

    /*将签名的16进制字符串转化为普通字符串*/    
    unsigned char sign_rev_int[257];
    unsigned char sign_rev_char[128];
    for (unsigned int i = 0; sign_rev[i]!='\0'; i++)
    {
    if(sign_rev[i]>='0'&&sign_rev[i]<='9')  
        sign_rev_int[i] = (unsigned int)(sign_rev[i]-'0');
    else if(sign_rev[i]>='a'&&sign_rev[i]<='f')  
        sign_rev_int[i] = (unsigned int)(sign_rev[i]-'a'+10);
    else if(sign_rev[i]>='A'&&sign_rev[i]<='F')  
        sign_rev_int[i] = (unsigned int)(sign_rev[i]-'A'+10);
    else {
        printf("received msg error!\n");
        exit_example(EXIT_SUCCESS, sockfd, NULL);
        return 0;
        }
    }

    for (unsigned int i = 0; i < 128; i++)
        sign_rev_char[i]=(unsigned char)(sign_rev_int[2*i]*16 + sign_rev_int[2*i+1]);   

    unsigned char digest_veri[SHA_DIGEST_LENGTH];
    hashMessage(digest_veri,veri_rev);
    printf("返回数据摘要：");
    for(unsigned int i =0;i<SHA_DIGEST_LENGTH;i++) 
    printf("%02x",digest_veri[i]);
    printf("\n\n");
    usleep(2000000U);

    /*读取平台公钥*/
    RSA *platpub= RSA_new();
    strcat(tmpath,"/key/smp_public_key.pem");
    platpub = getKey(platpub,tmpath,PEM_read_RSA_PUBKEY);
    cut=strstr(tmpath,"/key/smp_public_key.pem");
    *cut='\0';

    /*使用公钥验签*/
    ret = RSA_verify(NID_sha1, (unsigned char *)digest_veri, SHA_DIGEST_LENGTH, (const unsigned char *)sign_rev_char, sizeof(sign_rev_char), platpub);
    printf("使用平台公钥验签RSA_verify ret=%d\n\n",ret);
    RSA_free(platpub);
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
                exit_example(EXIT_SUCCESS, sockfd, NULL);
                return 0;
            } 
        }  
    else
        {
            printf("\033[1m\033[45;33m[7] 返回数据验签失败 Verify_Failed!\n    sever_msg:%s\033[0m\n\n",sever_msg);
            exit_example(EXIT_SUCCESS, sockfd, NULL); 
            return 0;
        }
    rev_msg[0]=0;//清空全局标志位
    return 0;
}
int measure(const char* addr, const char* port, const char* topic)
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
        unsigned char dig_img1[SHA_DIGEST_LENGTH]={0};
        hashMessage(dig_img1,buff_img1);
        char digHex_img1[SHA_DIGEST_LENGTH*2+1]={0};
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        sprintf(&digHex_img1[i*2], "%02x", (unsigned int)dig_img1[i]);
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
        unsigned char dig_img2[SHA_DIGEST_LENGTH]={0};
        hashMessage(dig_img2,buff_img2);
        char digHex_img2[SHA_DIGEST_LENGTH*2+1]={0};
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        sprintf(&digHex_img2[i*2], "%02x", (unsigned int)dig_img2[i]);
        printf("\033[1m\033[45;33m[4] 计算os镜像度量SHA值：\033[0m\n\n%s\n\n",digHex_img2);
        usleep(2000000U);

        /*拼接两个16进制的摘要*/
        unsigned char dig_comb[SHA_DIGEST_LENGTH]={0};
        unsigned char tmp_comb[SHA_DIGEST_LENGTH*4]={0};
        strcat((char *)tmp_comb,(const char *)digHex_img1);
        strcat((char *)tmp_comb,(const char *)digHex_img2);

        hashMessage(dig_comb,(char *)tmp_comb);
        char digHex_comb[SHA_DIGEST_LENGTH*2+1];
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        sprintf(&digHex_comb[i*2], "%02x", (unsigned int)dig_comb[i]);
        printf("\033[1m\033[45;33m[5] 计算bios及os镜像有序度量SHA值：\033[0m\n\n%s\n\n",digHex_comb);
        usleep(2000000U);
        
        /*create publish json data*/
        cJSON *root,*ml,*pcrs,*file1,*file2;   
        root=cJSON_CreateObject();        
        cJSON_AddStringToObject(root,"flag","measure");
        cJSON_AddStringToObject(root,"deviceid","chislab1"); 
        cJSON_AddItemToObject(root, "ML", ml=cJSON_CreateObject()); 

        cJSON_AddNumberToObject(ml,"length",2);
        cJSON_AddItemToObject(ml, "1", file1=cJSON_CreateObject()); 
        cJSON_AddItemToObject(ml, "2", file2=cJSON_CreateObject());

        cJSON_AddStringToObject(file1,"name","BIOS");
        cJSON_AddStringToObject(file1,"sha1",digHex_img1);
        cJSON_AddNumberToObject(file1,"PCR",1);

        cJSON_AddStringToObject(file2,"name","OS");
        cJSON_AddStringToObject(file2,"sha1",digHex_img2);
        cJSON_AddNumberToObject(file2,"PCR", 1);

        cJSON_AddItemToObject(root, "PCRs", pcrs=cJSON_CreateObject());
        cJSON_AddStringToObject(pcrs,"1",digHex_comb);
        char* out1=cJSON_Print(root);
        
        out1 = stringStrip(out1);//删除空格和换行

        unsigned char dig_json[SHA_DIGEST_LENGTH];
        hashMessage(dig_json,out1);

        /*读取设备私钥*/
        RSA *dpri= RSA_new();
        strcat(tmpath,"/key/dprikey.key");
        dpri = getKey(dpri,tmpath,PEM_read_RSAPrivateKey);
        cut=strstr(tmpath,"/key/dprikey.key");
        *cut='\0';

        /*加密度量json摘要*/
        unsigned char dig_encrypt[512]={0};
        unsigned int encryptlen;
        RSA_sign(NID_sha1, (unsigned char *)dig_json,SHA_DIGEST_LENGTH, dig_encrypt, (unsigned int *)&encryptlen,dpri);
        RSA_free(dpri);//删除私钥结构体

        char digHex_encrypt[512*2+1];
        for (unsigned int i = 0; i < encryptlen; i++)
        sprintf(&digHex_encrypt[i*2], "%02x", (unsigned int)dig_encrypt[i]);
        cJSON_AddStringToObject(root,"sign",digHex_encrypt); 
        char* meas_out = cJSON_Print(root);

        /* open the non-blocking TCP socket (connecting to the broker) */
        sockfd = open_nb_socket(addr, port);

         if (sockfd == -1) {
             perror("Failed to open socket: ");
            exit_example(EXIT_FAILURE, sockfd, NULL);
         }
         fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK);
        
        /* 度量发布客户端 */
        struct mqtt_client client;
        uint8_t sendbuf[2048]; 
        uint8_t recvbuf[1024]; 
        mqtt_init(&client, sockfd, sendbuf, sizeof(sendbuf), recvbuf, sizeof(recvbuf), publish_callback);
        mqtt_connect(&client, "measure_devices", NULL, NULL, 0, NULL, NULL, 0, 400);
        if (client.error != MQTT_OK) 
        {
            fprintf(stderr, "error: %s\n", mqtt_error_str(client.error));
            exit_example(EXIT_FAILURE, sockfd, NULL);
        }

        pthread_t client_daemon;
        if(pthread_create(&client_daemon, NULL, client_refresher, &client)) 
        {
            fprintf(stderr, "Failed to start client daemon.\n");
            exit_example(EXIT_FAILURE, sockfd, NULL);

         }
        mqtt_subscribe(&client, "devices/measurement/measure/res", 0);

        mqtt_publish(&client, topic, meas_out, strlen((const char *)meas_out), MQTT_PUBLISH_QOS_0);
        if (client.error != MQTT_OK) {
            fprintf(stderr, "error: %s\n", mqtt_error_str(client.error));
            exit_example(EXIT_FAILURE, sockfd, &client_daemon);
        }
        printf("\033[1m\033[45;33m[6] 设备发布度量消息:\033[0m\n\n");
        usleep(2000000U);
        printf("%s\n\n",meas_out);       
        cJSON_Delete(root);
        free(meas_out);  
        usleep(2000000U);
        
        printf("\033[1m\033[45;33m[7] 订阅消息并等待响应.....\033[0m\n\n");
        usleep(2000000U);
        int ret = setTimeout(10000000);
        if(ret==-1)
        exit_example(EXIT_SUCCESS, sockfd, NULL);

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
        strcpy(sign_rev,(cJSON_GetObjectItem(root_rev,"sign"))->valuestring);//读取签名
        char sever_msg[100];
        strcpy(sever_msg,(cJSON_GetObjectItem(root_rev,"msg"))->valuestring);//读取服务器返回消息
        cJSON_DeleteItemFromObject(root_rev,"sign");  
        char* veri_rev = cJSON_Print(root_rev);

        veri_rev = stringStrip(veri_rev);//删除空格和换行

        /*将签名的16进制字符串转化为普通字符串*/
        unsigned int sign_rev_int[256];
        unsigned char sign_rev_char[128];
        for (unsigned int i = 0; sign_rev[i]!='\0'; i++)
        {
        if(sign_rev[i]>='0'&&sign_rev[i]<='9')  
            sign_rev_int[i] = (unsigned int)(sign_rev[i]-'0');
        else if(sign_rev[i]>='a'&&sign_rev[i]<='f')  
            sign_rev_int[i] = (unsigned int)(sign_rev[i]-'a'+10);
        else if(sign_rev[i]>='A'&&sign_rev[i]<='F')  
            sign_rev_int[i] = (unsigned int)(sign_rev[i]-'A'+10);
        else {
            printf("received msg error!\n");
            exit_example(EXIT_SUCCESS, sockfd, &client_daemon);
            return 0;
            }
        }

        for (unsigned int i = 0; i < 128; i++)
            sign_rev_char[i]=(unsigned char)(sign_rev_int[2*i]*16 + sign_rev_int[2*i+1]);   

        unsigned char digest_veri[SHA_DIGEST_LENGTH];
        hashMessage(digest_veri,veri_rev);
        printf("返回数据摘要：");
        for(unsigned int i =0;i<SHA_DIGEST_LENGTH;i++) 
        printf("%02x",digest_veri[i]);
        printf("\n\n");
        usleep(2000000U);

        /*读取平台公钥*/
        RSA *platpub= RSA_new();
        strcat(tmpath,"/key/smp_public_key.pem");
        platpub = getKey(platpub,tmpath,PEM_read_RSA_PUBKEY);
        cut=strstr(tmpath,"/key/smp_public_key.pem");
        *cut='\0';

        ret = RSA_verify(NID_sha1, (unsigned char *)digest_veri, SHA_DIGEST_LENGTH, (const unsigned char *)sign_rev_char, sizeof(sign_rev_char), platpub);
        printf("使用平台公钥验签RSA_verify ret=%d\n\n",ret);
        RSA_free(platpub);
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
    const char* topic;
    /* get address (argv[1] if present) */
    if (argc > 1) {
        addr = argv[1];
    } else {
        //addr = "218.89.239.8";
        //addr = "127.0.0.1";
        //addr = "192.168.31.246";
        //addr = "192.168.31.170";
        addr = "47.112.10.111";
    }
    /* get port number (argv[2] if present) */
    if (argc > 2) {
        port = argv[2];
    } else {
        port = "1883";
    }
    /* get the topic name to publish */
    if (argc > 3) {
        topic = argv[3];
    } else {
        //topic = "devices/TC/measurement";
        topic = "devices/measurement/register";
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
    /*设备认证流程*/
    regist(addr, port, topic);
    /*设备度量流程*/
    measure(addr, port, "devices/measurement/measure");  
    exit_example(EXIT_SUCCESS, sockfd, NULL);
    return 0;
}