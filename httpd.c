#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <strings.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <fcntl.h>

#define ISspace(x) isspace((int)(x))
#define SERVER_STRING "Server: saoki's http/0.1.0\r\n" //定义个人server名称
int NUMBER_OF_WORKERS = 4;
int pipefd[64][2];
int pollingNumber = 0;

void *accept_request(void *client);
void bad_request(int);
void cat(int, FILE *);
void cannot_execute(int);
void error_handling(const char *);
void execute_cgi(int, const char *, const char *, const char *);
int get_line(int, char *, int);
void headers(int, const char *);
void not_found(int);
void serve_file(int, const char *);
int startup(u_short *);
void unimplemented(int);

/**
 * 请求导致服务器端口上的对accept()的调用
 * 返回：适当处理请求。
 * 参数：连接到客户端的套接字
 */
void *accept_request(void *from_client)
{
	int client = *(int *)from_client;
	char buf[BUFSIZ];
	int numchars;
	char method[255];
	char url[255];
	char path[512];
	size_t i, j;
	struct stat st;
	int cgi = 0; //判断是否是cgi
	char *query_string = NULL;

	numchars = get_line(client, buf, sizeof(buf));

	i = j = 0;
	while (!ISspace(buf[j]) && (i < sizeof(method) - 1))
	{
		//提取其中的请求方式
		method[i] = buf[j];
		i++;
		j++;
	}
	method[i] = '\0';
	//如果请求的方法不是 GET 或 POST 任意一个的话就直接发送 response 告诉客户端没实现该方法
	if (strcasecmp(method, "GET") && strcasecmp(method, "POST"))
	{
		unimplemented(client);
		return NULL;
	}

	if (strcasecmp(method, "POST") == 0)
		cgi = 1;

	i = 0;
	//跳过所有的空白字符(空格)
	while (ISspace(buf[j]) && (j < sizeof(buf)))
		j++;

	//然后把 URL 读出来放到 url 数组中
	while (!ISspace(buf[j]) && (i < sizeof(url) - 1) && (j < sizeof(buf)))
	{
		url[i] = buf[j];
		i++;
		j++;
	}
	url[i] = '\0';

	//GET请求url可能会带有?,有查询参数
	if (strcasecmp(method, "GET") == 0)
	{

		query_string = url;
		//去遍历这个 url，跳过字符 ？前面的所有字符，如果遍历完毕也没找到字符 ？则退出循环
		while ((*query_string != '?') && (*query_string != '\0'))
			query_string++;

		/* 如果有?表明是动态请求, 开启cgi */
		if (*query_string == '?')
		{
			cgi = 1;
			//从字符 ？ 处把字符串 url 给分隔会两份
			*query_string = '\0';
			//使指针指向字符 ？后面的那个字符
			query_string++;
		}
	}
	//将前面分隔两份的前面那份字符串，拼接在字符串htdocs的后面之后就输出存储到数组 path 中。相当于现在 path 中存储着一个字符串
	sprintf(path, "websiti%s", url);

	//如果 path 数组中的这个字符串的最后一个字符是以字符 / 结尾的话，就拼接上一个"index.html"的字符串。首页的意思
	if (path[strlen(path) - 1] == '/')
	{
		strcat(path, "index.html");
	}
	//在系统上去查询该文件是否存在
	if (stat(path, &st) == -1)
	{
		//如果不存在，那把这次 http 的请求后续的内容(head 和 body)全部读完并忽略
		while ((numchars > 0) && strcmp("\n", buf))
			numchars = get_line(client, buf, sizeof(buf));
		//然后返回一个找不到文件的 response 给客户端
		not_found(client);
	}
	else
	{
		if ((st.st_mode & S_IFMT) == S_IFDIR) //S_IFDIR代表目录
											  //如果请求参数为目录, 自动打开index.html
		{
			strcat(path, "/index.html");
		}

		//文件可执行
		if ((st.st_mode & S_IXUSR) ||
			(st.st_mode & S_IXGRP) ||
			(st.st_mode & S_IXOTH))
			//S_IXUSR:文件所有者具可执行权限
			//S_IXGRP:用户组具可执行权限
			//S_IXOTH:其他用户具可读取权限
			cgi = 1;

		if (!cgi)
			serve_file(client, path); //静态文件请求
		else
			execute_cgi(client, path, method, query_string); //cgi动态文件请求
	}

	close(client);
	//printf("connection close....client: %d \n",client);
	return NULL;
}

/**
 * 通知客户端它提出的请求有问题 发送400代码
 * 参数：客户端套接字
 */
void bad_request(int client)
{
	char buf[1024];
	sprintf(buf, "HTTP/1.0 400 BAD REQUEST\r\n");
	send(client, buf, sizeof(buf), 0);
	sprintf(buf, "Content-type: text/html\r\n");
	send(client, buf, sizeof(buf), 0);
	sprintf(buf, "\r\n");
	send(client, buf, sizeof(buf), 0);
	sprintf(buf, "<P>Your browser sent a bad request, ");
	send(client, buf, sizeof(buf), 0);
	sprintf(buf, "such as a POST without a Content-Length.\r\n");
	send(client, buf, sizeof(buf), 0);
}

/**
 * 将文件的全部内容放到套接字上。此函数是以UNIX“cat”命令命名的，因为它可能只需做一些像pipe、fork和exec（“cat”）之类的事情就更容易了。
 * 参数：客户端套接字描述符
 * 		指向cat的文件的文件指针
 */
void cat(int client, FILE *resource)
{
	//发送文件的内容
	char buf[1024];
	fgets(buf, sizeof(buf), resource);
	while (!feof(resource))
	{

		send(client, buf, strlen(buf), 0);
		fgets(buf, sizeof(buf), resource);
	}
}

/**
 * 通知客户端CGI脚本无法执行。发送500代码
 * 参数：客户端套接字描述符。
 */
void cannot_execute(int client)
{
	char buf[1024];
	sprintf(buf, "HTTP/1.0 500 Internal Server Error\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "Content-type: text/html\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "<P>Error prohibited CGI execution.\r\n");
	send(client, buf, strlen(buf), 0);
}

void error_handling(const char *msg)
{
	//包含于<stdio.h>,基于当前的 errno 值，在标准错误上产生一条错误消息。
	perror(msg);
	exit(1);
}

/**
 * 执行cgi动态解析，将需要将环境变量设置为合适的。
 * 参数：客户端套接字描述符
 * 		CGI脚本的路径 
 */
void execute_cgi(int client, const char *path,
				 const char *method, const char *query_string)
{

	char buf[1024];
	int cgi_output[2];
	int cgi_input[2];

	pid_t pid;
	int status;

	int i;
	char c;

	int numchars = 1;
	int content_length = -1;
	//默认字符
	buf[0] = 'A';
	buf[1] = '\0';
	//如果是 http 请求是 GET 方法的话读取并忽略请求剩下的内容
	if (strcasecmp(method, "GET") == 0)
	{
		while ((numchars > 0) && strcmp("\n", buf))
		{
			numchars = get_line(client, buf, sizeof(buf));
		}
	}
	else if (strcasecmp(method, "POST") == 0)
	{
		numchars = get_line(client, buf, sizeof(buf));
		//这个循环的目的是读出指示 body 长度大小的参数，并记录 body 的长度大小。其余的 header 里面的参数一律忽略
    	//注意这里只读完 header 的内容，body 的内容没有读
		while ((numchars > 0) && strcmp("\n", buf))
		{
			buf[15] = '\0';
			if (strcasecmp(buf, "Content-Length:") == 0)
				content_length = atoi(&(buf[16])); //记录 body 的长度大小

			numchars = get_line(client, buf, sizeof(buf));
		}

		//如果 http 请求的 header 没有指示 body 长度大小的参数，则报错返回
		if (content_length == -1)
		{
			bad_request(client);
			return;
		}
	}
	else /*HEAD or other*/
  {
    //TODO:其他请求
  }

	sprintf(buf, "HTTP/1.0 200 OK\r\n");
	send(client, buf, strlen(buf), 0);
	//下面这里创建两个管道，用于两个进程间通信
	if (pipe(cgi_output) < 0)
	{
		cannot_execute(client);
		return;
	}
	if (pipe(cgi_input) < 0)
	{
		cannot_execute(client);
		return;
	}

	//创建一个子进程
	if ((pid = fork()) < 0)
	{
		cannot_execute(client);
		return;
	}
	if (pid == 0) /* 子进程: 运行CGI 脚本 */
	{
		char meth_env[255];
		char query_env[255];
		char length_env[255];
		//将子进程的输出由标准输出重定向到 cgi_ouput 的管道写端上
		dup2(cgi_output[1], 1);
		//将子进程的输出由标准输入重定向到 cgi_ouput 的管道读端上
		dup2(cgi_input[0], 0);
		//关闭 cgi_ouput 管道的读端与cgi_input 管道的写端
		close(cgi_output[0]); //关闭了cgi_output中的读通道
		close(cgi_input[1]);  //关闭了cgi_input中的写通道

		sprintf(meth_env, "REQUEST_METHOD=%s", method);
		//putenv()包含于<stdlib.h>中，参读《TLPI》P128
    	//将这个环境变量加进子进程的运行环境中
		putenv(meth_env);
		//根据http 请求的不同方法，构造并存储不同的环境变量
		if (strcasecmp(method, "GET") == 0)
		{
			//存储QUERY_STRING
			sprintf(query_env, "QUERY_STRING=%s", query_string);
			putenv(query_env);
		}
		else
		{ /* POST */
			//存储CONTENT_LENGTH
			sprintf(length_env, "CONTENT_LENGTH=%d", content_length);
			putenv(length_env);
		}
		//最后将子进程替换成另一个进程并执行 cgi 脚本
		execl(path, path, NULL); //执行CGI脚本
		exit(0);
	}
	else
	{
		//父进程则关闭了 cgi_output管道的写端和 cgi_input 管道的读端
		close(cgi_output[1]);
		close(cgi_input[0]);
		//如果是 POST 方法的话就继续读 body 的内容，并写到 cgi_input 管道里让子进程去读
		if (strcasecmp(method, "POST") == 0)

			for (i = 0; i < content_length; i++)
			{

				recv(client, &c, 1, 0);

				write(cgi_input[1], &c, 1);
			}

		//读取cgi脚本返回数据
		while (read(cgi_output[0], &c, 1) > 0)
		//发送给浏览器
		{
			send(client, &c, 1, 0);
		}

		//运行结束关闭
		close(cgi_output[0]);
		close(cgi_input[1]);

		waitpid(pid, &status, 0);
	}
}

/**
 * 解析一行http报文，从套接字获取一行，无论该行是否以换行符结尾，
 * 回车或CRLF组合。终止读取的字符串
 * 为空字符。如果在换行符之前未找到换行符
 * 缓冲区的末尾，字符串以null终止。如果有
 * 读取上面的三行终止符，即最后一个字符
 * 字符串将是换行符，并且字符串将以终止
 * 空字符。
 * 参数：套接字描述符
 * 将数据保存到的缓冲区
 * 缓冲区的大小
 * 返回：存储的字节数（不包括null）
 */
int get_line(int sock, char *buf, int size)
{
	int i = 0;
	char c = '\0';
	int n;

	while ((i < size - 1) && (c != '\n'))
	{
		//读一个字节的数据存放在 c 中
		n = recv(sock, &c, 1, 0);
		if (n > 0)
		{
			if (c == '\r')
			{

				n = recv(sock, &c, 1, MSG_PEEK);
				if ((n > 0) && (c == '\n'))
					recv(sock, &c, 1, 0);
				else
					c = '\n';
			}
			buf[i] = c;
			i++;
		}
		else
			c = '\n';
	}
	buf[i] = '\0';
	return (i);
}

/**
 * 返回有关文件的信息性HTTP标头。 
 * 参数：用于在其上打印标题的套接字
 * 		文件名 
 */
void headers(int client, const char *filename)
{

	char buf[1024];

	(void)filename; /* could use filename to determine file type */
	//发送HTTP头
	strcpy(buf, "HTTP/1.0 200 OK\r\n");
	send(client, buf, strlen(buf), 0);
	strcpy(buf, SERVER_STRING);
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "Content-Type: text/html\r\n");
	send(client, buf, strlen(buf), 0);
	strcpy(buf, "\r\n");
	send(client, buf, strlen(buf), 0);
}

/**
 * 网页没有找到，发送404代码
 * 参数：客户端套接字
 */
void not_found(int client)
{
	char buf[1024];
	sprintf(buf, "HTTP/1.0 404 NOT FOUND\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, SERVER_STRING);
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "Content-Type: text/html\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "<HTML><TITLE>Not Found</TITLE>\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "<BODY><P>The server could not fulfill\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "your request because the resource specified\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "is unavailable or nonexistent.\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "</BODY></HTML>\r\n");
	send(client, buf, strlen(buf), 0);
}

//如果不是CGI文件，也就是静态文件，直接读取文件返回给请求的http客户端
void serve_file(int client, const char *filename)
{
	FILE *resource = NULL;
	int numchars = 1;
	char buf[1024];
	buf[0] = 'A';
	buf[1] = '\0';
	while ((numchars > 0) && strcmp("\n", buf))
	{
		numchars = get_line(client, buf, sizeof(buf));
	}

	//打开文件
	resource = fopen(filename, "r");
	if (resource == NULL)
		not_found(client);
	else
	{
		headers(client, filename);
		cat(client, resource);
	}
	fclose(resource); //关闭文件句柄
}


/**
 * 此功能开始侦听Web连接的过程
 * 在指定的端口上。如果端口为0，则动态分配一个
 * port并修改原始的port变量以反映实际端口。
 * 参数：指向包含要连接的端口的变量的指针
 * 返回：套接字
 */
int startup(u_short *port)
{
	int httpd = 0, option;
	struct sockaddr_in name;
	//设置http socket
	httpd = socket(PF_INET, SOCK_STREAM, 0);
	if (httpd == -1)
		error_handling("socket"); //连接失败
	socklen_t optlen;
	optlen = sizeof(option);
	option = 1;
	setsockopt(httpd, SOL_SOCKET, SO_REUSEADDR, (void *)&option, optlen);

	memset(&name, 0, sizeof(name));
	name.sin_family = AF_INET;
	name.sin_port = htons(*port);
	name.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(httpd, (struct sockaddr *)&name, sizeof(name)) < 0)
		error_handling("bind"); //绑定失败
	 if (*port == 0 )  /*动态分配一个端口 */
	 {
		socklen_t namelen = sizeof(name);
		if (getsockname(httpd, (struct sockaddr *)&name, &namelen) == -1)
			error_handling("getsockname");
		*port = ntohs(name.sin_port);
	 }

	 if (listen(httpd, 5) < 0)
	  error_handling("listen");
	 return(httpd);
}

/**
 * 通知客户端尚未请求的Web方法
 * 实施的。
 * 参数：客户端套接字
 */
void unimplemented(int client)
{
	char buf[1024];
	//发送501说明相应方法没有实现
	sprintf(buf, "HTTP/1.0 501 Method Not Implemented\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, SERVER_STRING);
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "Content-Type: text/html\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "<HTML><HEAD><TITLE>Method Not Implemented\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "</TITLE></HEAD>\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "<BODY><P>HTTP request method not supported.\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "</BODY></HTML>\r\n");
	send(client, buf, strlen(buf), 0);
}

/**
 * 设置文件描述符属性为非阻塞状态
 * 参数：文件描述符
 * 返回：文件描述符旧属性
 */
int setnonblocking(int fd)
{

	int old_option = fcntl(fd, F_GETFL);
	int new_option = old_option | O_NONBLOCK;
	fcntl(fd, F_SETFL, new_option);
	return old_option;
}



/**
 * 工作线程函数，通过epoll方式I/O复用，处理http请求；
 * 参数：该线程id标识
 */
void *workThread(void *fid)
{

	int id = *(int *)fid;
	int epfd, nfds, client_sock;
	struct epoll_event ev, events[20];
	ev.data.fd = pipefd[id][0];
	ev.events = EPOLLIN | EPOLLET; //采用边缘触发

	epfd = epoll_create(5);
	epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[id][0], &ev);
	char buf[BUFSIZ];

	printf("create successfully pthread:%d\n", id);

	while (1)
	{
		//TODO:数值多大合适？
		nfds = epoll_wait(epfd, events, 200, 100);
		for (int i = 0; i < nfds; i++)
		{
			if (events[i].data.fd == pipefd[id][0]) //有新的连接进入
			{
				if (read(pipefd[id][0], buf, BUFSIZ) == -1)
				{
					error_handling("working_read_pipe() error!");
				}
				client_sock = atoi(buf);
				ev.data.fd = client_sock;
				ev.events = EPOLLIN | EPOLLET;
				setnonblocking(client_sock); //epoll_ET模式需要非阻塞状态
				epoll_ctl(epfd, EPOLL_CTL_ADD, client_sock, &ev);
				//printf("add client: %d to epoll : %d\n",client_sock,id);
			}
			else if (events[i].events & EPOLLIN) //有http请求
			{
				//printf("accept %d\n",events[i].data.fd);
				accept_request((void *)&events[i].data.fd);
				epoll_ctl(epfd, EPOLL_CTL_DEL, events[i].data.fd, &ev); //http为无状态协议，一次请求即可关闭
			}
		}
	}
}

int main(int argv, char *argc[])
{
	int server_sock = -1;
	u_short port = 1735; //默认监听端口号 port 为1735
	int client_sock = -1;
	struct sockaddr_in client_addr;
	socklen_t client_addr_len = sizeof(client_addr);
	pthread_t newthread[64];

	server_sock = startup(&port);
	//忽略SIGPIPE信号，导致服务器被关闭
	signal(SIGPIPE, SIG_IGN);

	printf("http server_sock is %d\n", server_sock);
	printf("http running on port %d\n", port);

	//设置工作线程数量，默认为4，最大64
	if (argv == 2)
	{
		NUMBER_OF_WORKERS = atoi(argc[1]) > 64 ? 64 : atoi(argc[1]);
		printf("Thread : %d\n", NUMBER_OF_WORKERS);
	}

	//启动工作线程，并创建线程间通行管道
	for (int i = 0; i < NUMBER_OF_WORKERS; i++)
	{
		if (pthread_create(&newthread[i], NULL, workThread, (void *)&i) != 0)
			perror("pthread_create");
		if (pipe(pipefd[i]) == -1)
		{
			error_handling("pipe()_error");
		}
		//TODO：这里防止创建的进程获取到相同id，后面可以改成锁
		sleep(1);
	}

	//负责监听客户端连接，并通过轮询方式，派发给工作线程
	while (1)
	{

		client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_addr_len);

		//printf("New connection..sock: %d  ip: %s , port: %d\n", client_sock, inet_ntoa(client_addr.sin_addr),ntohs(client_addr.sin_port));
		if (client_sock == -1)
			error_handling("accept");

		char sockbuf[33];
		sprintf(sockbuf, "%d", client_sock);
		//轮询派发任务
		write(pipefd[pollingNumber++][1], sockbuf, sizeof(client_sock));

		//pollingNumber %= NUMBER_OF_WORKERS;
		if (pollingNumber == NUMBER_OF_WORKERS)
			pollingNumber = 0;

		/* 每个连接创建一个线程去处理，效率低
		if (pthread_create(&newthread , NULL, accept_request, (void*)&client_sock) != 0) {
		   perror("pthread_create");	 
		 }
		*/
	}
	close(server_sock);
	return (0);
}
