#include "openfetion.h"

#define FETION_NO "123456"
#define FETION_PWD "pwd"

//#define PROXY_ENABLE 0

void myfx_conn_append(FetionConnection *conn)
{
        struct conn_list *tmp;
        tmp = (struct conn_list*)malloc(sizeof(struct conn_list));
        tmp->conn = conn;

        connlst->next->pre = tmp;
        tmp->next = connlst->next;
        tmp->pre = connlst;
        connlst->next = tmp;
}
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
	int old_state;
	int presence_count;
	struct userlist *ul;

	FetionConnection *conn = NULL;						// connection for sipc
	char *pos, *nonce, *key, *aeskey, *response;		// string for auth
	Config *config = NULL;								// global user config
	Group *group = NULL;								// buddy list
	User *user = NULL;									// global user info
	char code[20];										// store reply code
	char statusTooltip[128];
	struct userlist *newul;
	struct userlist *ul_cur;

	int state = 0;
	int remember = 0;	//TODO:
	
	int local_buddy_count = 0;
	int local_group_count = 0;
	int new_buddy_count = 0;
	int new_group_count = 0;

	old_state = state;
	user = fetion_user_new(FETION_NO, FETION_PWD);
	printf("Preparing for login\n");
	config = fetion_config_new();

	ul = fetion_user_list_load(config);

	if(!user){
		printf("Login failed.\n");
		goto failed;
	}

#ifdef PROXY_ENABLE 	
	Proxy *proxy = NULL;
	proxy = (Proxy *)malloc(sizeof(Proxy));
	memset(proxy, 0, sizeof(proxy));
	proxy->proxyEnabled = 1;
	strcpy(proxy->proxyHost, "proxy.bupt.edu.cn");
	proxy->proxyPort = 8080;
	strcpy(proxy->proxyUser, "gaolei");
	strcpy(proxy->proxyPass, "gaolei");
	config->proxy = proxy;
#else
	config->proxy = NULL;
#endif

	fetion_user_set_config(user, config);

login:
	pos = ssi_auth_action(user);
	if(!pos){
		printf("Login failed.\n");
		goto failed;
	}
	parse_ssi_auth_response(pos, user);
	free(pos);
	if(user->loginStatus == 421 || user->loginStatus == 420){
		debug_info(user->verification->text);
		debug_info(user->verification->tips);
		printf("Getting code picture, please wait...\n");
		generate_pic_code(user);
		strcpy(code, "1234");	//TODO: verifycode
		fetion_user_set_verification_code(user , code);
		debug_info("Input verfication code:%s" , code);
	        goto login;
	}
        if(user->loginStatus == 401 ||
                user->loginStatus == 400 ||
                user->loginStatus == 404){
                debug_info("password ERROR!!!");
                printf("Login failed. \nIncorrect cell phone number or password\n");
                goto failed;
        }
	printf("Loading local user information\n"); 
	fetion_config_initialize(config, user->userId);

        /* set user list to be stored in local file      */
        newul = fetion_user_list_find_by_no(ul , FETION_NO);
        if(!newul){
                if(remember)
                        newul = fetion_user_list_new(FETION_NO,
                                                  FETION_PWD, user->userId,
                                                  user->sId, state , 1);
                else
                        newul = fetion_user_list_new(FETION_NO,
                                                  NULL, user->userId,
                                                  user->sId, state , 1);
                foreach_userlist(ul , ul_cur)
                        ul_cur->islastuser = 0;
                fetion_user_list_append(ul , newul);
        }else{
                memset(newul->password,
                                 0, sizeof(newul->password));
                if(remember)
                        strcpy(newul->password , FETION_PWD);
                newul->laststate = state;
                foreach_userlist(ul , ul_cur)
                        ul_cur->islastuser = 0;
                newul->islastuser = 1;
        }
        fetion_user_list_save(config , ul);
        fetion_user_list_free(ul);

        /* download xml configuration file from the server */
        fetion_config_load(user);
        if(config->sipcProxyPort == 0)
                printf("It detected that this`s this first time you login\ndownloading configuration file...\n");
        else
                printf("Downloading configuration files");
        if(fetion_config_download_configuration(user) < 0){
                printf("Connection has been shutdown by the server");
                return -1;
        }
        fetion_config_save(user);

	fetion_user_set_st(user, state);

	/*load local data */
	fetion_user_load(user);
	fetion_contact_load(user, &local_group_count, &local_buddy_count);

	/* start a new tcp connection for registering to sipc server */
	conn = tcp_connection_new();
	if(config->proxy != NULL && config->proxy->proxyEnabled){
		printf("Connecting to proxy server\n");
		tcp_connection_connect_with_proxy(conn, config->sipcProxyIP, config->sipcProxyPort, config->proxy);
	}
	else{
		printf("Connecting to registaration server\n");
		tcp_connection_connect(conn, config->sipcProxyIP, config->sipcProxyPort);
	}

        /* add the connection object into the connection list */
//        myfx_conn_append(conn);

        /* initialize a sip object */
	FetionSip *sip = fetion_sip_new(conn, user->sId);
	fetion_user_set_sip(user, sip);
	printf("Registering to SIPC Server\n");
	pos = sipc_reg_action(user);
	if(!pos){
		printf("Login Failed\n");
		goto failed;
	}
	parse_sipc_reg_response(pos, &nonce, &key);
	free(pos);
	aeskey = generate_aes_key();
	response = generate_response(nonce, user->userId, user->password, key, aeskey);
	free(nonce);
	free(key);
	free(aeskey);

	/* start sipc authentication using the response created just now */
	printf("SIPC Identity\n");
auth:
	pos = sipc_aut_action(user, response);
	if(pos == NULL){
		printf("Login Failed\n");
		goto failed;
	}
	if(parse_sipc_auth_response(pos, user,
			&new_group_count, &new_buddy_count) < 0){
		debug_info("Password error, login failed!!!");
		printf("Password error, login failed!!!\n");
		goto failed;
	}
	free(pos); pos = NULL;
	if(user->loginStatus == 401 || user->loginStatus == 400){
		debug_info("Password error, login failed!!!");
		printf("Authenticate failed.\n");
		goto failed;
	}
	if(user->loginStatus == 421 || user->loginStatus == 420){
		debug_info(user->verification->text);
		debug_info(user->verification->tips);
		printf("Getting code picture, please wait...");
		generate_pic_code(user);
                strcpy(code, "1234");   //TODO: verifycode
                fetion_user_set_verification_code(user , code);
		goto auth;
                debug_info("Input verfication code:%s" , code);
	}

        Contact *c_cur;
        Contact *c_tmp;
        Group   *g_cur;
        Group   *g_tmp;

        /* update buddy list */
        if(user->groupCount == 0)
                user->groupCount = local_group_count;
        else if(user->groupCount != local_group_count){
                for(g_cur = user->groupList->next;
                                g_cur != user->groupList;){
                        g_tmp = g_cur;
                        g_cur = g_cur->next;
                        if(!g_tmp->dirty){
                                fetion_group_list_remove(g_tmp);
                                free(g_tmp);
                        }
                }
        }

        /* update buddy count */
        if(user->contactCount == 0)
                user->contactCount = local_buddy_count;
        else if(user->contactCount != local_buddy_count){
                /* do some clean on the local buddy data */
                for(c_cur = user->contactList->next;
                                c_cur !=  user->contactList;){
                        c_tmp = c_cur;
                        c_cur = c_cur->next;
                        if(!c_tmp->dirty){
                                fetion_contact_list_remove(c_tmp);
                                free(c_tmp);
                        }
                }
        }
	
	pg_group_get_list(user);

	printf("Login successful\n");

        /*if there is not a buddylist name "Ungrouped" or "Strangers", create one */
        if(fetion_group_list_find_by_id(user->groupList,
                        BUDDY_LIST_NOT_GROUPED) == NULL &&
                    fetion_contact_has_ungrouped(user->contactList)){
                group = fetion_group_new();
                group->groupid = BUDDY_LIST_NOT_GROUPED;
                strcpy(group->groupname , "Ungrouped");
                fetion_group_list_append(user->groupList , group);
        }
        if(fetion_group_list_find_by_id(user->groupList,
                        BUDDY_LIST_STRANGER) == NULL &&
                        fetion_contact_has_strangers(user->contactList)){
                group = fetion_group_new();
                group->groupid = BUDDY_LIST_STRANGER;
                strcpy(group->groupname , "Strangers");
                fetion_group_list_prepend(user->groupList , group);
        }

	printf("Your IP is %s\nLast login IP is %s\nLast Login Time is %s\n", user->publicIp, user->lastLoginIp, user->lastLoginTime);

	pthread_attr_t * thAttr = NULL;
	pthread_t tid;
	int ret;
    	pthread_create(&tid, thAttr, (void *)myThread, user); 
//	recvMsg(user);
	pthread_join(tid,NULL);
	return 0;

failed:
	return -1;
}
/*
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
//	        FILE *fp=popen("/usr/lib/sendmail -t > /dev/null","w");
//        	fprintf(fp,"To: %s\n","lostleon@gmail.com, wangz2020@gmail.com");
//        	fprintf(fp,"To: %s\n","lostleon@gmail.com, wangz2020@gmail.com");
//        	fprintf(fp,"From: %s\n","wangz2020@gmail.com");
//        	fprintf(fp, "Reply-to: %s\n","wangz2020@gmail.com");
//		fprintf(fp, "Content-type: %s\n", "text/html;charset=utf-8");
//        	fprintf(fp,"Subject: %s\n","您有新的飞信消息，请查收");
//        	fprintf(fp,"%s\n",pos->message);
//        	pclose(fp);

			}
			pos = pos->next;
		}
		if(msg != NULL)
			fetion_sip_message_free(msg);
	}
}
*/
