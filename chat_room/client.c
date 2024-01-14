#pragma GCC diagnostic ignored "-Wformat-truncation"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <pthread.h>
#include <time.h>
#include <termios.h>
#include "lib/cJSON.h"
#include "lib/cJSON.c"

#define SERV_TCP_PORT 12345
#define MAX_SIZE 2048
#define CLEAR_SCREEN "clear" // 清屏命令(Linux)

// 枚举表示客户端的不同状态, 如初始化、菜单、发送消息等
typedef enum
{
    STATUS_MENU,
    STATUS_LOGIN,
    STATUS_REGIST,
    STATUS_QUIT,
    STATUS_SEND_MSG
} ClientState;

// 枚举表示客户端和服务器之间的消息类型，如初始化消息、菜单消息、发送消息等。
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

int sockfd;         // 全局套接字变量
int user_id;        // 全局用户ID变量
char user_name[64]; // 全局变量 user_name

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER; // 初始化互斥锁

// 清屏函数
void clearScreen()
{
    system(CLEAR_SCREEN);
}

// 检查输入是否有效：非空，且仅包含字母、数字和下划线
int isValidInput(const char *input)
{
    if (input[0] == '\0')
        return 0; // 检查是否为空字符串
    for (int i = 0; input[i] != '\0'; i++)
    {
        if (!isalnum(input[i]) && input[i] != '_')
            return 0; // 只允许字母、数字和下划线
    }
    return 1;
}

// 获取用户输入的用户名和密码
void getUsernameAndPassword(char *username, char *password)
{
    // 获取并验证用户名
    do
    {
        printf("请输入用户名（只能包含字母、数字和下划线）：");
        fgets(username, MAX_SIZE, stdin);
        username[strcspn(username, "\n")] = 0; // 移除换行符
        if (!isValidInput(username))
        {
            printf("输入不合法，请重新输入。\n");
        }
    } while (!isValidInput(username));

    // 获取并验证密码
    do
    {
        printf("请输入密码（只能包含字母、数字和下划线）：");
        fgets(password, MAX_SIZE, stdin);
        password[strcspn(password, "\n")] = 0; // 移除换行符
        if (!isValidInput(password))
        {
            printf("输入不合法，请重新输入。\n");
        }
    } while (!isValidInput(password));
}

// cJSON 处理函数封装
void sendJsonMessage(int sockfd, cJSON *jsonObject)
{
    char *jsonString = cJSON_Print(jsonObject);
    // printf("Sending JSON: %s\n", jsonString); // 添加打印语句
    write(sockfd, jsonString, strlen(jsonString));
    free(jsonString);
}

// 向服务器发送注册信息
void sendRegistrationInfo(int sockfd, const char *username, const char *password)
{
    cJSON *jsonObject = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonObject, "username", username);
    cJSON_AddStringToObject(jsonObject, "password", password);
    cJSON_AddNumberToObject(jsonObject, "message_type", MSG_REGIST);
    sendJsonMessage(sockfd, jsonObject);
    cJSON_Delete(jsonObject);
}

// 在客户端接收并显示消息
void receive_and_display_messages()
{
    char response[MAX_SIZE];

    while (1)
    {
        int bytes_received = read(sockfd, response, MAX_SIZE);
        if (bytes_received <= 0)
        {
            break;
        }
        response[bytes_received] = '\0';
        // printf("接收广播响应：%s\n", response);

        cJSON *message = cJSON_Parse(response);
        if (message == NULL)
        {
            // 处理无效 JSON 数据的情况
            printf("\n无效的 JSON 数据：%s\n", response);
        }
        else
        {
            // 继续处理有效的 JSON 数据
            int message_type = cJSON_GetObjectItem(message, "message_type")->valueint;

            // 加锁以确保线程安全
            pthread_mutex_lock(&mutex);

            if (message_type == MSG_BROADCAST)
            {
                const int userId = cJSON_GetObjectItem(message, "user_id")->valueint;
                const char *content = cJSON_GetObjectItem(message, "content")->valuestring;

                printf("\r[用户 %d]: %s\n", userId, content);

                // 打印下一行的提示符
                printf(">>> ");
                fflush(stdout); // 确保输出被立即打印
            }

            pthread_mutex_unlock(&mutex);
            cJSON_Delete(message);
        }
    }
}

// 客户端菜单状态
ClientState fun_st1_menu()
{
    int input, ch; // ch 用于清除输入缓冲区中的字符
    printf("===== 聊天室服务系统 ======\n");
    printf("1 登录\n");
    printf("2 注册\n");
    printf("3 退出系统\n");
    printf("==========================\n");
    printf("请输入您的选择: ");

    while (1)
    {
        // 使用 getchar 读取单个字符
        input = getchar();

        // 清除输入缓冲区中的回车符和换行符
        while ((ch = getchar()) != '\n' && ch != EOF)
            ;

        if (input == '1')
        {
            return STATUS_LOGIN;
        }
        else if (input == '2')
        {
            return STATUS_REGIST;
        }
        else if (input == '3')
        {
            printf("正在退出, 请稍等....\n");
            return STATUS_QUIT;
        }
        else
        {
            // 处理不合法的输入
            printf("输入不合法!!请重新输入: ");
        }
    }
}

// 客户端登录状态
ClientState fun_st2_login()
{
    // 初始化 cJSON 对象
    cJSON *jsonObject = cJSON_CreateObject();

    char username[MAX_SIZE];
    char password[MAX_SIZE];
    printf("========= 登录 =========\n");
    getUsernameAndPassword(username, password); // 获取用户输入的用户名和密码

    // 将用户名和密码添加到 cJSON 对象
    cJSON_AddStringToObject(jsonObject, "username", username);
    cJSON_AddStringToObject(jsonObject, "password", password);
    // 将消息类型添加到 cJSON 对象
    cJSON_AddNumberToObject(jsonObject, "message_type", MSG_LOGIN);

    // 使用封装的函数发送 cJSON 对象
    sendJsonMessage(sockfd, jsonObject);
    cJSON_Delete(jsonObject); // 释放 cJSON 对象内存

    // 从服务器接收响应
    char response[MAX_SIZE];
    read(sockfd, response, MAX_SIZE);

    cJSON *response_json = cJSON_Parse(response); // 解析响应为 cJSON 对象
    if (!response_json)
    {
        printf("服务器响应解析失败。\n");
        return STATUS_MENU;
    }

    cJSON *status_item = cJSON_GetObjectItem(response_json, "message_type");
    if (!status_item)
    {
        printf("无法获取服务器响应的消息类型。\n");
        cJSON_Delete(response_json);
        return STATUS_MENU;
    }

    int response_type = status_item->valueint;
    if (response_type == MSG_LOGIN)
    {
        cJSON *user_id_item = cJSON_GetObjectItem(response_json, "data");
        if (user_id_item)
        {
            cJSON *actual_user_id_item = cJSON_GetObjectItem(user_id_item, "user_id");
            user_id = actual_user_id_item->valueint; // 存储用户 ID 到全局变量
            strcpy(user_name, username);             // 更新全局用户名
            clearScreen();
            printf("登录成功！欢迎 %d 号用户, %s。\n", user_id, username);
            cJSON_Delete(response_json);
            return STATUS_SEND_MSG;
        }
        else
        {
            printf("响应中未包含用户ID。\n");
        }
    }
    else if (response_type == MSG_LOGIN_FAILED)
    {
        printf("登录失败! 请检查您的用户名和密码!\n");
    }

    cJSON_Delete(response_json); // 释放 cJSON 对象内存
    return STATUS_MENU;
}

// 客户端注册状态
ClientState fun_st2_regist()
{
    char username[MAX_SIZE];
    char password[MAX_SIZE] = {0}; // 初始化为空字符串
    cJSON *response_json, *status_item;
    char response[MAX_SIZE];
    int response_type;

    printf("========= 注册 =========\n");

    // 获取并验证用户名和密码
    getUsernameAndPassword(username, password);

    // 向服务器发送注册信息
    sendRegistrationInfo(sockfd, username, password);

    // 从服务器接收响应
    read(sockfd, response, MAX_SIZE);

    // 打印原始服务器响应
    printf("原始服务器响应: %s\n", response);

    response_json = cJSON_Parse(response);
    if (!response_json)
    {
        printf("服务器响应解析失败。\n");
        return STATUS_MENU;
    }

    status_item = cJSON_GetObjectItem(response_json, "message_type");
    if (!status_item)
    {
        printf("服务器响应格式错误。\n");
        cJSON_Delete(response_json);
        return STATUS_MENU;
    }

    response_type = status_item->valueint;
    if (response_type == MSG_REGIST_FAILED)
    {
        printf("用户名已存在，请尝试使用其他用户名。\n");
        cJSON_Delete(response_json);
        return STATUS_MENU;
    }
    else if (response_type == MSG_REGIST)
    {
        printf("注册成功! 您的用户ID为: %d\n", cJSON_GetObjectItem(cJSON_GetObjectItem(response_json, "data"), "user_id")->valueint);
        cJSON_Delete(response_json);
        return STATUS_MENU; // 注册成功，返回到主菜单
    }

    printf("未知错误，请重试。\n");
    cJSON_Delete(response_json);
    return STATUS_MENU;
}

// 客户端退出状态
ClientState fun_st2_quit()
{
    // 创建请求JSON对象
    cJSON *request = cJSON_CreateObject();
    cJSON_AddNumberToObject(request, "message_type", MSG_QUIT);
    cJSON_AddNumberToObject(request, "user_id", user_id);

    // 使用封装的函数发送退出请求到服务器
    sendJsonMessage(sockfd, request);
    cJSON_Delete(request); // 释放 cJSON 对象内存

    // 关闭套接字
    close(sockfd);
    printf("已退出系统。\n");
    exit(0);

    return STATUS_QUIT; // 返回退出状态（虽然实际上永远不会执行到这里）
}

// 客户端聊天状态
ClientState fun_st3_send_msg()
{
    char message[MAX_SIZE];
    char input;

    printf("=== 用户：%s  编号：%d  已登录，输入 exit 表示退出聊天 ===\n", user_name, user_id);
    printf(">>> ");

    // 启动接收并显示消息的线程
    pthread_t receive_thread;
    if (pthread_create(&receive_thread, NULL, (void *)receive_and_display_messages, NULL) != 0)
    {
        perror("Error creating receive thread");
        return STATUS_SEND_MSG;
    }

    while (fgets(message, MAX_SIZE, stdin) != NULL)
    {
        message[strcspn(message, "\n")] = 0; // 移除换行符
        if (strcmp(message, "exit") == 0)
        {
            // 等待接收线程退出
            pthread_cancel(receive_thread);
            pthread_join(receive_thread, NULL);
            clearScreen();
            return STATUS_MENU; // 用户选择退出，返回到菜单
        }

        if (strlen(message) > 0)
        {
            cJSON *jsonObject = cJSON_CreateObject();
            cJSON_AddNumberToObject(jsonObject, "user_id", user_id);
            cJSON_AddStringToObject(jsonObject, "content", message);
            cJSON_AddNumberToObject(jsonObject, "message_type", MSG_SEND);
            sendJsonMessage(sockfd, jsonObject);
            cJSON_Delete(jsonObject);
        }

        pthread_mutex_lock(&mutex);
        printf(">>> ");
        pthread_mutex_unlock(&mutex);
    }

    return STATUS_MENU;
}

int main(int argc, char *argv[])
{
    clearScreen();                   // 清屏
    ClientState state = STATUS_MENU; // 初始化状态
    struct sockaddr_in serv_addr;    // 服务器地址信息
    char *serv_host = "localhost";   // 默认服务器主机名
    struct hostent *host_ptr;        // 主机信息的指针
    int port = SERV_TCP_PORT;        // 端口号

    // 如果有至少两个参数，将第二个参数视为服务器主机名
    if (argc >= 2)
        /* 取 host 变量 */
        serv_host = argv[1]; // 如果没有设置，程序将连接到本地主机 localhost
    if (argc == 3)           // 如果有三个参数，将第三个参数视为端口号
        /* 取 port 变量 */
        sscanf(argv[2], "%d", &port);
    else
        port = SERV_TCP_PORT; // 否则使用默认端口号

    /* 取 host 的主机地址 */
    if ((host_ptr = gethostbyname(serv_host)) == NULL)
    {
        perror("gethostbyname error");
        exit(1);
    }

    // 检查主机地址类型是否为 IPv4（AF_INET）
    if (host_ptr->h_addrtype != AF_INET)
    {
        perror("unknown address type");
        exit(1);
    }

    // 初始化 serv_addr 结构
    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr =
        ((struct in_addr *)host_ptr->h_addr_list[0])->s_addr;
    serv_addr.sin_port = htons(port);

    // 创建套接字
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("can't open stream socket");
        exit(1);
    }

    // 连接到服务器
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("can't connect to server");
        exit(1);
    }

    // 发送数据到服务器
    char message[MAX_SIZE];
    char response[MAX_SIZE];
    char username[MAX_SIZE];
    char password[MAX_SIZE];

    while (1)
    {
        switch (state)
        {
        case STATUS_MENU:
            state = fun_st1_menu(); // 处理主菜单逻辑
            break;
        case STATUS_LOGIN:
            state = fun_st2_login(); // 处理登录逻辑
            break;
        case STATUS_REGIST:
            state = fun_st2_regist(); // 处理注册逻辑
            break;
        case STATUS_QUIT:
            state = fun_st2_quit(); // 处理退出程序逻辑
            break;
        case STATUS_SEND_MSG:
            state = fun_st3_send_msg(); // 处理发送消息逻辑
            break;
        }
    }
    return 0;
}
