#include "fetion_include.h"
//#define FETION_NO "998797517"
//#define FETION_PWD "zzz812531"
#define FETION_NO "13718999799"
#define FETION_PWD "11jysk1"
//#define FETION_NO "552584216"
//#define FETION_PWD "11jysk1"
//#define PROXY_ENABLE 1

void recvMsg();
void myThread(User *user){
	sleep(180);
	for(;;){
                if(fetion_user_keep_alive(user) < 0){
		        debug_info("网络连接已断开,请重新登录");
                	return;
                }
		sleep(180);
	}
	pthread_exit(NULL);
} 

int main(){
	FetionConnection *conn = NULL;
	char *pos, *nonce, *key, *aeskey, *response;
	Config *config = NULL;
	User *user = NULL;
	printf("Start logging in...\n");	
	config = fetion_config_new();
	user = fetion_user_new(FETION_NO, FETION_PWD);
	Proxy *proxy = NULL;
	proxy = (Proxy *)malloc(sizeof(Proxy));
	memset(proxy, 0, sizeof(proxy));
	proxy->proxyEnabled = 1;
	strcpy(proxy->proxyHost, "proxy.bupt.edu.cn");
	proxy->proxyPort = 8080;
	strcpy(proxy->proxyUser, "gaolei");
	strcpy(proxy->proxyPass, "gaolei");

	if(user == NULL){
		printf("Login failed.\n");
		return -1;
	}
	config->proxy = NULL;
	fetion_user_set_config(user, config);

login:
	pos = ssi_auth_action(user);
	if(pos == NULL){
		printf("Login failed.\n");
		return -1;
	}
	parse_ssi_auth_response(pos, user);
	free(pos);
	printf("loginStatus: %d\n", user->loginStatus);

	fetion_config_initialize(config, user->userId);
	fetion_config_download_configuration(user);
	if(fetion_config_load_xml(user) < 0){
		printf("Login Failed.\n");
		return -1;
	}
	fetion_config_load_data(user);
		
	conn = tcp_connection_new();
	if(0){
		printf("Starting connecting to proxy server.\n");
		tcp_connection_connect_with_proxy(conn, config->sipcProxyIP, config->sipcProxyPort, proxy);
	}
	else{
		printf("starting connecting to registar server.\n");
		tcp_connection_connect(conn, config->sipcProxyIP, config->sipcProxyPort);
	}
	FetionSip *sip = fetion_sip_new(conn, user->sId);
	fetion_user_set_sip(user, sip);
	printf("Start registering to the SIPC server.\n");
	pos = sipc_reg_action(user);
	if(pos == NULL){
		printf("Login Failed\n");
		return -1;
	}
	parse_sipc_reg_response(pos, &nonce, &key);
	free(pos);
	aeskey = generate_aes_key();
	response = generate_response(nonce, user->userId, user->password, key, aeskey);
	free(nonce);
	free(key);
	free(aeskey);

	printf("start authenticating the SIPC identity\n");
auth:
	pos = sipc_aut_action(user, response);
	if(pos == NULL){
		printf("Login Failed.\n");
		return -1;
	}
	if(parse_sipc_auth_response(pos, user) < 0){
		printf("Password error, login failed!!!\n");
		return -1;
	}
	free(pos); pos = NULL;
	if(user->loginStatus == 401 || user->loginStatus == 400){
		printf("Password error, login failed!!!");
		return -1;
	}
	if(user->loginStatus == 421 || user->loginStatus == 420){
		printf("GOT %d\n", user->loginStatus);
		debug_info(user->verification->text);
		debug_info(user->verification->tips);
		
//		debug_info("Input verfication code: %s", code);
		return -1;
	}
	printf("Login OK.\n");
	printf("Your IP is %s\nLast login IP is %s\nLast Login Time is %s\n", user->publicIp, user->lastLoginIp, user->lastLoginTime);

	pthread_attr_t * thAttr = NULL;
	pthread_t tid;
	int ret;
    	pthread_create(&tid, thAttr, (void *)myThread, user); 
	recvMsg(user);
	pthread_join(tid,NULL);
	return 0;
}

void recvMsg(User *user){
	FetionSip *sip = user->sip;
	int type;
	SipMsg *msg, *pos;
	fd_set fd_read;
	int ret;
	Message *sipmsg;

	for(;;){
		FD_ZERO(&fd_read);
		FD_SET(sip->tcp->socketfd, &fd_read);
		ret = select (sip->tcp->socketfd+1, &fd_read, NULL, NULL, NULL);
		if (ret == -1 || ret == 0) {
			debug_info ("Error.. to read socket");
		}
		if (!FD_ISSET (sip->tcp->socketfd, &fd_read)) {
			sleep (100);
			continue;
		}
		msg = fetion_sip_listen(sip);
		pos = msg;
		while(pos != NULL){
			type = fetion_sip_get_type(pos->message);
			switch(type){
				case SIP_NOTIFICATION :
					//fx_main_process_notification(fxmain , pos->message);
					//printf("%s\n", pos->message);
					break;
				case SIP_MESSAGE:
					//fx_main_process_message(fxmain , sip , pos->message);
					//printf("%s\n", pos->message);
					sipmsg = NULL;
					fetion_sip_parse_message(sip, pos->message, &sipmsg);
					break;
				case SIP_INVITATION:
					//fx_main_process_invitation(fxmain , pos->message);
					//printf("%s\n", pos->message);
					break;
				case SIP_INCOMING :
					//fx_main_process_incoming(fxmain , sip , pos->message);
					//printf("%s", pos->message);
					break;
				case SIP_SIPC_4_0:
					//printf("%s", pos->message);
					break;
				default:
					//printf("%s\n" , pos->message);
					break;
			}

			int position = strspn(pos->message, "M");
			debug_info("#################___%d__%d" , position, type);
			debug_info("%s\n\n\n\n", pos->message);	
			if(position == 1){
            //sendmail
	        FILE *fp=popen("/usr/lib/sendmail -t > /dev/null","w");
        	fprintf(fp,"To: %s\n","lostleon@gmail.com, wangz2020@gmail.com");
//        	fprintf(fp,"To: %s\n","lostleon@gmail.com, wangz2020@gmail.com");
        	fprintf(fp,"From: %s\n","wangz2020@gmail.com");
        	fprintf(fp, "Reply-to: %s\n","wangz2020@gmail.com");
		fprintf(fp, "Content-type: %s\n", "text/html;charset=utf-8");
        	fprintf(fp,"Subject: %s\n","您有新的飞信消息，请查收");
        	fprintf(fp,"%s\n",pos->message);
        	pclose(fp);

			}
			pos = pos->next;
		}
		if(msg != NULL)
			fetion_sip_message_free(msg);
	}
}

