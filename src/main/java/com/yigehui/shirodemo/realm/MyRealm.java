package com.yigehui.shirodemo.realm;

import org.apache.shiro.authc.*;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

public class MyRealm extends AuthorizingRealm {
    private static Logger log = LoggerFactory.getLogger(MyRealm.class);
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        //这里是授权
        log.info("本地realm的授权方法");
        String username = (String)this.getAvailablePrincipal(principals);
        Set<String> roleNames = new HashSet<String>();
        Set<String> permissions = new HashSet<String>();
        if("admin".equals(username)){
            roleNames.add("admin");
            permissions.add("edit");
            permissions.add("read");
        }else{
            roleNames.add("user");
            roleNames.add("read");
        }
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        info.setStringPermissions(permissions);
        info.setRoles(roleNames);
        return info;
    }
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        log.info("本地realm的登录方法");
        UsernamePasswordToken utoken = (UsernamePasswordToken) token;
        String username = utoken.getUsername();
        String password = null;
        //取数据库获取密码
        if("admin".equals(username)){
            password = "8279603faf7658fded36ce6a400df107";
        }else if("user".equals(username)){
            password = "fe317ae688b790a7caed039618d028cb";
        }
        SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(utoken.getPrincipal(),password,getName());
        info.setCredentialsSalt(ByteSource.Util.bytes(username));
        return info;
    }
}
