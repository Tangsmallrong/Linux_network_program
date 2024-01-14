#pragma GCC diagnostic ignored "-Wformat-truncation"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <zlib.h>
#include "lib/cJSON.h"
#include "lib/cJSON.c"

#define SERV_TCP_PORT 12345
#define MAX_SIZE 2048
#define USER_INFO_FILE "user.json" // 用于存储用户信息的文件名
#define MAX_CLIENTS 10

// 定义链表节点，用于存储客户端信息
struct ClientNode
{
    int user_id;
    int sockfd;
    struct ClientNode *next;
};
// 定义全局链表头
struct ClientNode *clients = NULL;

typedef enum
{
    MSG_LOGIN,
    MSG_REGIST,
    MSG_QUIT,
    MSG_LOGIN_FAILED,
    MSG_REGIST_FAILED,
    MSG_SEND,
    MSG_BROADCAST // 新增的消息类型，用于广播消息给其他用户
} MessageType;

// 用于存储用户信息的结构
typedef struct
{
    int id;
    char username[MAX_SIZE];
    char password[MAX_SIZE];
} User;

int sockfd;         // 全局套接字
cJSON *root = NULL; // 创建 cJSON 对象用于存储用户信息

pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;      // 初始化互斥锁
pthread_mutex_t online_users_mutex = PTHREAD_MUTEX_INITIALIZER; // 初始化互斥锁
pthread_mutex_t user_info_mutex = PTHREAD_MUTEX_INITIALIZER;    // 初始化用于用户信息的互斥锁

// 读取用户信息
void readUsers()
{

    FILE *file = fopen(USER_INFO_FILE, "r");
    if (file == NULL)
    {
        // 文件不存在，创建一个新的JSON对象并保存到文件中
        root = cJSON_CreateObject();
        cJSON_AddArrayToObject(root, "users");
        file = fopen(USER_INFO_FILE, "w"); // 创建新文件
        if (file != NULL)
        {
            char *json_str = cJSON_Print(root);
            fprintf(file, "%s", json_str);
            free(json_str);
            fclose(file);
        }
        return;
    }

    // 读取整个文件内容
    fseek(file, 0, SEEK_END);
    long len = ftell(file);
    if (len == 0)
    {
        // 文件为空，初始化空的JSON对象
        root = cJSON_CreateObject();
        cJSON_AddArrayToObject(root, "users");
    }
    else
    {
        // 读取并解析JSON数据
        fseek(file, 0, SEEK_SET);
        char *buffer = (char *)malloc(len + 1);
        fread(buffer, 1, len, file);
        buffer[len] = '\0';

        root = cJSON_Parse(buffer);
        if (!root)
        {
            // 解析失败，初始化空的JSON对象
            root = cJSON_CreateObject();
            cJSON_AddArrayToObject(root, "users");
        }
        else
        {
            // 解析成功，处理用户数据
            cJSON *users = cJSON_GetObjectItem(root, "users");
            int n_users = cJSON_GetArraySize(users);
            for (int i = 0; i < n_users; i++)
            {
                cJSON *user = cJSON_GetArrayItem(users, i);
                cJSON *user_id = cJSON_GetObjectItem(user, "user_id");
                cJSON *username = cJSON_GetObjectItem(user, "username");
                cJSON *password = cJSON_GetObjectItem(user, "password");

                if (user_id && username && password)
                {
                    printf("User ID: %d, Username: %s, Password: %s\n",
                           user_id->valueint, username->valuestring, password->valuestring);
                }
            }
        }
        free(buffer);
    }
    fclose(file);
}

// 生成新用户的 id
int generateNewUserId()
{
    int max_id = 0;
    cJSON *users = cJSON_GetObjectItem(root, "users");
    cJSON *user = NULL;

    cJSON_ArrayForEach(user, users)
    {
        cJSON *idObj = cJSON_GetObjectItem(user, "user_id");
        if (idObj != NULL && idObj->valueint > max_id)
        {
            max_id = idObj->valueint;
        }
    }

    return max_id + 1; // 返回当前最大ID加一作为新用户ID
}

// 保存用户信息到 JSON 文件
void saveUsers()
{
    pthread_mutex_lock(&user_info_mutex); // 加锁以保证线程安全

    FILE *file = fopen(USER_INFO_FILE, "w");
    if (file == NULL)
    {
        perror("Error opening user.json");
        pthread_mutex_unlock(&user_info_mutex); // 解锁
        return;
    }

    char *jsonString = cJSON_Print(root);
    if (jsonString != NULL)
    {
        fprintf(file, "%s", jsonString);
        free(jsonString);
    }
    else
    {
        printf("cJSON_Print 返回空\n");
    }

    if (fclose(file) != 0) // 检查 fclose 是否成功
    {
        perror("Error closing file");
    }
    else
    {
        printf("文件已成功关闭\n");
    }

    pthread_mutex_unlock(&user_info_mutex); // 解锁
}

// 函数用于将客户端添加到链表
void addClient(int user_id, int sockfd)
{
    struct ClientNode *newNode = (struct ClientNode *)malloc(sizeof(struct ClientNode));
    newNode->user_id = user_id;
    newNode->sockfd = sockfd;
    newNode->next = NULL;

    pthread_mutex_lock(&clients_mutex);
    if (clients == NULL)
    {
        clients = newNode;
    }
    else
    {
        struct ClientNode *current = clients;
        while (current->next != NULL)
        {
            current = current->next;
        }
        current->next = newNode;
    }
    pthread_mutex_unlock(&clients_mutex);
}

// 函数用于从链表中移除客户端
void removeClient(int sockfd)
{
    pthread_mutex_lock(&clients_mutex);
    struct ClientNode *current = clients;
    struct ClientNode *previous = NULL;

    while (current != NULL)
    {
        if (current->sockfd == sockfd)
        {
            if (previous == NULL)
            {
                clients = current->next;
            }
            else
            {
                previous->next = current->next;
            }
            free(current);
            break;
        }
        previous = current;
        current = current->next;
    }
    pthread_mutex_unlock(&clients_mutex);
}

// 函数用于广播消息给所有在线用户，除了发送者自己
void broadcastMessageToAllExceptSender(int sender_user_id, const char *content)
{
    pthread_mutex_lock(&clients_mutex);
    struct ClientNode *current = clients;

    while (current != NULL)
    {
        if (current->user_id != sender_user_id)
        {
            cJSON *broadcast_data = cJSON_CreateObject();
            cJSON_AddNumberToObject(broadcast_data, "user_id", sender_user_id);
            cJSON_AddStringToObject(broadcast_data, "content", content);
            cJSON_AddNumberToObject(broadcast_data, "message_type", MSG_BROADCAST);

            char *broadcastString = cJSON_Print(broadcast_data);
            if (broadcastString != NULL)
            {
                write(current->sockfd, broadcastString, strlen(broadcastString));
                free(broadcastString);
            }

            cJSON_Delete(broadcast_data);
        }

        current = current->next;
    }

    pthread_mutex_unlock(&clients_mutex);
}

// 根据用户ID查找对应的用户名
char *getUsernameFromUserID(int user_id)
{
    cJSON *users = cJSON_GetObjectItem(root, "users");
    if (users == NULL)
    {
        return NULL; // 没有找到用户信息
    }

    int num_users = cJSON_GetArraySize(users);

    for (int i = 0; i < num_users; i++)
    {
        cJSON *user = cJSON_GetArrayItem(users, i);
        cJSON *idObj = cJSON_GetObjectItem(user, "user_id");
        cJSON *usernameObj = cJSON_GetObjectItem(user, "username");

        if (idObj && usernameObj && idObj->valueint == user_id)
        {
            return usernameObj->valuestring;
        }
    }

    return NULL; // 未找到匹配的用户名
}

// 创建 cJSON 响应对象
cJSON *createResponse(MessageType message_type, const char *message, cJSON *data)
{
    cJSON *response = cJSON_CreateObject();

    // 添加消息类型到响应
    cJSON_AddNumberToObject(response, "message_type", message_type);

    // 添加消息内容到响应
    cJSON_AddStringToObject(response, "message", message);

    // 添加用户数据（如果提供的话）
    if (data)
    {
        cJSON_AddItemToObject(response, "data", data);
    }

    return response;
}

// 处理 MSG_LOGIN 类型的消息
cJSON *handleLoginMessage(cJSON *request, int client_fd)
{
    cJSON *response = NULL;

    // 从请求中获取用户名和密码
    const char *username = cJSON_GetObjectItem(request, "username")->valuestring;
    const char *password = cJSON_GetObjectItem(request, "password")->valuestring;

    // 遍历用户信息，检查用户名和密码是否匹配
    int login_failed = 1; // 标识登录是否失败
    cJSON *users = cJSON_GetObjectItem(root, "users");
    cJSON *user = NULL;

    cJSON_ArrayForEach(user, users)
    {
        cJSON *idObj = cJSON_GetObjectItem(user, "user_id");
        cJSON *userObj = cJSON_GetObjectItem(user, "username");
        cJSON *passwordObj = cJSON_GetObjectItem(user, "password");

        if (userObj && passwordObj &&
            strcmp(userObj->valuestring, username) == 0 &&
            strcmp(passwordObj->valuestring, password) == 0)
        {
            printf("用户: ID=%d, 用户名=%s, 密码=%s\n",
                   idObj->valueint, userObj->valuestring, passwordObj->valuestring);

            login_failed = 0;

            // 如果登录成功，返回用户ID
            cJSON *response_data = cJSON_CreateObject();
            cJSON_AddNumberToObject(response_data, "user_id", idObj->valueint);
            response = createResponse(MSG_LOGIN, "登录成功", response_data);

            // 将用户ID和套接字添加到链表
            addClient(idObj->valueint, client_fd);
            break;
        }
    }

    if (login_failed)
    {
        printf("用户: %s 登录失败\n", username);
        response = createResponse(MSG_LOGIN_FAILED, "登录失败", NULL);
    }

    // 打印 response
    printf("客户端响应: %s\n", cJSON_Print(response));

    return response;
}

// 处理 MSG_REGIST 类型的消息
cJSON *handleRegistMessage(cJSON *request, int client_fd)
{
    cJSON *response = NULL;
    const char *username = cJSON_GetObjectItem(request, "username")->valuestring;
    const char *password = cJSON_GetObjectItem(request, "password")->valuestring;

    // 检查用户名是否已存在
    cJSON *users = cJSON_GetObjectItem(root, "users");
    cJSON *user = NULL;
    int user_exists = 0;

    cJSON_ArrayForEach(user, users)
    {
        cJSON *userObj = cJSON_GetObjectItem(user, "username");
        if (userObj && strcmp(userObj->valuestring, username) == 0)
        {
            user_exists = 1;
            break;
        }
    }

    if (user_exists)
    {
        // 用户名已存在
        response = createResponse(MSG_REGIST_FAILED, "用户名已存在", NULL);
    }
    else
    {
        // 注册新用户
        cJSON *new_user = cJSON_CreateObject();

        // 生成新的用户ID
        int new_user_id = generateNewUserId();
        cJSON_AddNumberToObject(new_user, "user_id", new_user_id);
        // printf("生成的新用户ID: %d\n", new_user_id); // 打印新生成的用户ID
        cJSON_AddStringToObject(new_user, "username", username);
        cJSON_AddStringToObject(new_user, "password", password);

        cJSON_AddItemToArray(users, new_user);

        printf("新用户添加到用户列表\n"); // 打印新用户添加到列表的消息

        // 创建成功的响应
        cJSON *data = cJSON_CreateObject();
        cJSON_AddNumberToObject(data, "user_id", new_user_id);
        response = createResponse(MSG_REGIST, "注册成功", data);

        // 保存用户信息到文件
        saveUsers();
    }

    return response;
}

// 处理 MSG_SEND 类型的消息
cJSON *handleSendMessage(cJSON *request)
{
    cJSON *response = NULL; // 存储将要生成的响应

    int user_id = cJSON_GetObjectItem(request, "user_id")->valueint;
    const char *content = cJSON_GetObjectItem(request, "content")->valuestring;
    char *username = getUsernameFromUserID(user_id);

    printf("接收到来自用户 %s (ID: %d) 的消息: %s\n", username, user_id, content);

    // 调用广播消息函数，将消息发送给其他用户
    broadcastMessageToAllExceptSender(user_id, content);

    response = createResponse(MSG_SEND, "消息发送成功", NULL);

    // printf("返回响应：%s\n", cJSON_Print(response));

    return response;
}

// 处理 MSG_QUIT 类型的消息
cJSON *handleQuitMessage(cJSON *request, int client_fd)
{
    cJSON *response = createResponse(MSG_QUIT, "退出系统!", NULL);
    int user_id = cJSON_GetObjectItem(request, "user_id")->valueint;

    // 加锁
    pthread_mutex_lock(&online_users_mutex);

    // 关闭连接，删除链表中的在线用户
    removeClient(client_fd);

    // 解锁
    pthread_mutex_unlock(&online_users_mutex);

    return response;
}

// 服务线程
void *serviceThread(void *arg)
{
    // 将传递给线程的套接字描述符的指针解引用为整数
    int client_sockfd = *((int *)arg);
    free(arg); // 释放之前分配的套接字描述符的内存

    cJSON *request = NULL;  // 存储客户端请求的 JSON 数据
    cJSON *response = NULL; // 存储要发送给客户端的 JSON 响应
    char buffer[MAX_SIZE];  // 存储从客户端接收到的消息

    while (1)
    {
        memset(buffer, 0, MAX_SIZE); // 清空缓冲区

        // 读取客户端消息
        if (read(client_sockfd, buffer, MAX_SIZE) <= 0)
        {
            // 关闭连接，删除链表中的在线用户
            removeClient(client_sockfd);
            break; // 读取失败，说明客户端关闭连接或发生错误，跳出循环，退出服务线程
        }

        // 解析 JSON 请求
        request = cJSON_Parse(buffer);
        // 打印接收到的客户端数据
        printf("客户端发送的 json 请求: %s\n", buffer);
        // 解析 JSON 请求
        if (request == NULL)
        {
            // 解析失败，发送错误响应
            response = createResponse(MSG_QUIT, "Invalid JSON request", NULL);
        }

        // 获取消息类型
        int message_type = cJSON_GetObjectItem(request, "message_type")->valueint;

        // 处理不同类型的消息
        switch (message_type)
        {
        case MSG_LOGIN:
        {
            response = handleLoginMessage(request, client_sockfd);
            break;
        }
        case MSG_REGIST:
        {
            response = handleRegistMessage(request, client_sockfd);
            break;
        }
        case MSG_SEND:
        {
            response = handleSendMessage(request);
            break;
        }
        case MSG_QUIT:
        {
            response = handleQuitMessage(request, client_sockfd);
            break;
        }
        default:
            response = createResponse(MSG_QUIT, "消息类型不合法", NULL);
            break;
        }

        if (response != NULL)
        {
            char *responseString = cJSON_Print(response);

            // 发送 JSON 响应到客户端
            write(client_sockfd, responseString, strlen(responseString));

            free(responseString);
            cJSON_Delete(response);
        }
        cJSON_Delete(request);
    }

    close(client_sockfd); // 关闭客户端套接字
    return NULL;
}

int main(int argc, char *argv[])
{
    struct sockaddr_in cli_addr, serv_addr;
    // 端口号 port、消息长度 len、套接字描述符 sockfd、新套接字描述符 newsockfd、客户端地址信息的长度 clilen
    int port, len, sockfd, newsockfd, clilen;

    // 设置端口号
    if (argc == 2)
        /* 读取命令行参数的端口号 */
        sscanf(argv[1], "%d", &port);
    else
        port = SERV_TCP_PORT;

    // 读取用户信息
    readUsers();

    // 创建套接字
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("can't open stream socket");
        exit(1);
    }

    // 设置服务器地址信息
    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERV_TCP_PORT);
    serv_addr.sin_addr.s_addr = INADDR_ANY;

    // 绑定套接字, 本地地址的绑定，ip+端口号, 不可重复
    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("can't bind local address");
        exit(1);
    }

    // 开始监听
    listen(sockfd, 5); // 让服务器套接字开始监听传入的连接请求，允许同时处理最多5个等待连接的客户端
    printf("Server listening on port %d...\n", SERV_TCP_PORT);

    while (1)
    {
        // 等待客户端连接
        clilen = sizeof(cli_addr);
        // 一旦有客户端连接，它会接受连接并创建一个新的套接字描述符 newsockfd 用于与客户端通信
        newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);

        // 创建线程为新客户服务
        pthread_t thread;
        int *new_sock = malloc(sizeof(int));
        *new_sock = newsockfd;
        if (pthread_create(&thread, NULL, serviceThread, (void *)new_sock) < 0)
        {
            perror("Could not create thread");
            return 1;
        }
    }

    // 服务器退出时的清理工作
    saveUsers(); // 保存用户信息
    cJSON_Delete(root);
    close(sockfd);

    return 0;
}
