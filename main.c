#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <cjson/cJSON.h>
#include <mqtt.h>
#include <posix_sockets.h>

const char * deviceID;//获取shell当中的环境变量设备ID
char rev_msg[1024]={0};//获取订阅消息变量
char rev_msg2[1024]={0};//存储设备发来的数据
char tmpTopic[50] = {0};//拼接各个主题
int sockfd = -1;//socket句柄

char* dpath = NULL;//项目文件路径
char* tmpath = NULL;//拼接各类路径
char* cut = NULL;//裁剪拼接字符串

const char* addr;//broker地址
const char* port;//broker端口
int server_port;//本地TCP服务端口

struct mqtt_client client;
pthread_t client_daemon;
pthread_mutex_t mutex;

int serverSocket;
int clientSocket;
pthread_t id, id2;

char devsendbuf[2048]={0};
char devrecvbuf[2048]={0};

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

    send(clientSocket, "quit\n", strlen("quit\n"), 0);
    close(serverSocket);

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

/* 数据发送线程*/
int thread_send(int Client,char* msg)
{   
    printf("msg_send:%s\n\n",msg);
    send(Client, msg, strlen(msg), 0);
    return 0;
}

/* 数据接收线程*/
int thread_recv(int Client)
{
    int IDataNum;
    char tmpbuf[1024];
    while(1)
    { 
        memset(tmpbuf,0,1024); 
        IDataNum = recv(Client, tmpbuf, 1024, 0);
        if(IDataNum < 1) 
            continue;
        printf("msg_rev:%s\n",tmpbuf );
        strcpy(devrecvbuf,tmpbuf); 
    }
    return 0;
}


int msgExchange(const char* topic)
{       
    while(devrecvbuf[0]==0);//等待设备发送数据
    printf("\033[1m\033[45;33m[1] 接收到设备数据及长度:\033[0m\n\n");
    printf("msg_rev：%s\nlength:%ld\n\n", devrecvbuf,strlen(devrecvbuf));
    printf("\033[1m\033[45;33m[2] 发布消息:\033[0m\n\n");
    printf("%s\n\n",devrecvbuf);
    mqtt_publish(&client, topic, devrecvbuf, strlen((const char *)devrecvbuf), MQTT_PUBLISH_QOS_0); 
    memset(devrecvbuf,0,2048);  
    if (client.error != MQTT_OK) 
    {
        fprintf(stderr, "error: %s\n", mqtt_error_str(client.error));
        exit_example(EXIT_FAILURE, sockfd, &client_daemon);
    }   
    printf("\033[1m\033[45;33m[3] 等待响应.....\033[0m\n\n");
    int ret = setTimeout(10000000,devrecvbuf);
    if(ret==-1)
        exit_example(EXIT_SUCCESS, sockfd, &client_daemon);    

    printf("\033[1m\033[45;33m[4] 服务器返回消息:\033[0m\n\n");
    printf("rev_msg:");
    for (unsigned int i = 0; i < strlen(rev_msg); i++)
    printf("\033[1m\033[45;32m%c\033[0m", rev_msg[i]);
    printf("\n\n");
    usleep(2000000U);
    printf("\033[1m\033[45;33m[5] 返回设备数据\033[0m\n\n");
    //thread_send(clientSocket,rev_msg);//发回给设备
    strcat(rev_msg2,rev_msg);
    int len =strlen(rev_msg2);
    rev_msg2[len]='\n';
    //if(strstr(rev_msg,"success")== NULL||strstr(rev_msg,"trust")== NULL)//校验失败结束程序
    //   exit_example(EXIT_FAILURE, sockfd, &client_daemon);    
    memset(rev_msg,0,1024); 
    return 0;
}

int deviceVeri() 
{
    dpath = getenv("DPATH");
    //printf("dpath:%s\n",dpath ); 
    tmpath= dpath;
    deviceID = getenv("DEVICEID");
    sockfd = open_nb_socket(addr, port);
    if (sockfd == -1) {
        perror("Failed to open socket: ");
        exit_example(EXIT_FAILURE, sockfd, NULL);
    }
    fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK);

    /*建立mqtt客户端*/
    uint8_t mqsendbuf[1024]; 
    uint8_t mqrecvbuf[1024]; 
    mqtt_init(&client, sockfd, mqsendbuf, sizeof(mqsendbuf), mqrecvbuf, sizeof(mqrecvbuf), publish_callback); 
    
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
    printf("\033[1m\033[45;33m-------------------------------------------\033[0m\n\n");
    printf("               \033[1m\033[45;33m设备认证流程\033[0m              \n\n");
    printf("\033[1m\033[45;33m-------------------------------------------\033[0m\n\n");
    memset(tmpTopic,0,sizeof(tmpTopic));
    snprintf(tmpTopic,sizeof(tmpTopic),"%s%s%s","devices/",deviceID,"/regist"); 
    msgExchange(tmpTopic);

    /*设备度量流程*/
    printf("\033[1m\033[45;33m-------------------------------------------\033[0m\n\n");
    printf("               \033[1m\033[45;33m设备度量流程\033[0m              \n\n");
    printf("\033[1m\033[45;33m-------------------------------------------\033[0m\n\n");
    memset(tmpTopic,0,sizeof(tmpTopic));
    snprintf(tmpTopic,sizeof(tmpTopic),"%s%s%s","devices/",deviceID,"/measure"); 
    msgExchange(tmpTopic);
    printf("\033[1m\033[45;33m返回全部数据:\033[0m\n\n");
    thread_send(clientSocket,rev_msg2);//发回给设备
    return 0;
}

int main(int argc, const char *argv[]) 
{  
    printf("\033[1m\033[45;33m----------------------------------------\033[0m\n\n");
    printf("       \033[1m\033[45;33m终端设备认证、度量演示程序\033[0m       \n\n");
    printf("\033[1m\033[45;33m----------------------------------------\033[0m\n\n");
     
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

    if (argc > 3) {
        server_port = atoi(argv[3]);
    } else {
        server_port = 8003;
    }

    struct sockaddr_in server_addr;
    struct sockaddr_in clientAddr;
    int addr_len = sizeof(clientAddr);
 
    
    if((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket");
        return -1;
    }
    bzero(&server_addr, sizeof(server_addr));
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    /*ip可是是本服务器的ip，也可以用宏INADDR_ANY代替，代表0.0.0.0，表明所有地址*/
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    int on=1;  
    if((setsockopt(serverSocket,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)))<0)  
    {  
        perror("setsockopt failed");  
        exit(EXIT_FAILURE);  
    }     
    if(bind(serverSocket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("connect");
        return -1;
    }
    //设置服务器上的socket为监听状态
    if(listen(serverSocket, 5) < 0)
    {
    perror("listen");
    return -1;
    }
    printf("监听端口: %d\n", server_port);
    clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, (socklen_t*)&addr_len);
    if(clientSocket < 0)
    {
    perror("accept");
    return -1;
    }
    printf("IP is %s\n", inet_ntoa(clientAddr.sin_addr));
    printf("Port is %d\n", htons(clientAddr.sin_port));
    printf("等待消息...\n");
    pthread_create(&id,NULL,(void *)thread_recv,(void *)(intptr_t)clientSocket);
    pthread_create(&id2,NULL,(void *)deviceVeri,NULL);
    pthread_join(id2,NULL);
    close(serverSocket);
    close(clientSocket);
    exit_example(EXIT_SUCCESS, sockfd, &client_daemon);
    return 0;
}


