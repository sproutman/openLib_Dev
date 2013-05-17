#!/usr/bin/python  
################################################  
ldap_auth
################################################  
 
import sys  
import os  
import logging  
import ldap  
 
# settings for ldap  
ldap_uri = "ldap://127.0.0.1:389" 
ldap_starttls = True 
ldap_dn = "cn=%s,ou=users,ou=accounts,dc=intra,dc=etiantian,dc=org" 
 
# settings for logging  
log_filename = "/tmp/check_old1boy.log" 
log_format = "%(asctime)s %(levelname)s %(message)s" 
log_level = logging.DEBUG  
 
# settings for authorization  
auth_filename = "/etc/openvpn/old-boy-users.conf" 
 
def get_users(fpath):  
    fp = open(fpath, "rb")  
    lines = fp.readlines()  
    fp.close()  
    users = {}  
    for line in lines:  
        line = line.strip()  
        if len(line) <= 0 or line.startswith('#'):  
            continue 
        users[line] = True 
    return users  
 
def get_credits(fpath):  
    fp = open(fpath, "rb")  
    lines = fp.readlines()  
    fp.close()  
    assert len(lines)>=2, "invalid credit file" 
    username = lines[0].strip()  
    password = lines[1].strip()  
    return (username, password)  
 
def check_credits(username, password):  
    passed = False 
    ldap.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)  
    l = ldp.initialize(ldap_uri)  
    if ldap_starttls:  
        l.start_tls_s()  
    try:  
        l.simple_bind_s(ldap_dn % (username,), password)  
        passed = True 
    except ldap.INVALID_CREDENTIALS, e:  
        logging.error("username/password failed verifying")  
    l.unbind()  
    return passed  
 
def main(argv):  
    credit_fpath = argv[1]  
    (username,password) = get_credits(credit fpath)  
    if len(username) <= 0  or len(password) <= 0   
        logging.error("invalid creadits for user '%s'" % username)  
        return 1 
    logging.info("user '%s' request logining" % username)  
    if check_credits(username, password):  
        users = get_users(auth_filename)  
        if not username in users:  
            logging.error("user '%s' not authorized to access" % username)  
            return 1 
        logging.info("access of user '%s' granted" % username)  
        return 0 
    else:  
        logging.error("access of user '%s' denied" % username)  
        return 1 
 
if __name__ = "__main__":  
    logging.Config(format=logformat,filename=log_filename,level=log_level)  
    if len(sys.argv) != 2:  
        logging.fatal("usage: %s <credit-file>" % sys.argv[0])  
        sys.exit(1)  
    rcode = 1 
    try:  
        rcode = main(sys.argv)  
    except Exception   :  
        logging.fatal("exception happened: %s" % str())  
        rcode = 1 
    sys.exit(rcode)  

提示：在VPN配置中通过auth-user...参数调用脚本，简单配置下就可以实现通过LDAP认证了。效果很好，可以写PHP页面授权给行政人员管理（邮件），
网管来管理（内部VPN,SAMBA,FTP,SVN）,小运维（外部，服务器账户，SVN,VPN等）。