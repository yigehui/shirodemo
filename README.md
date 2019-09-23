

##  shiro源码分析

> shiro是一个有apache开发的安全框架，里面封装了认证和授权的多种方法，可以通过简单配置web项目的拦截器，就能对所有链接实现权限控制，以及登录认证的框架。

###  基本概念

1. Subject是shiro状态返回的对象， 里面包括很多权限相关的方法。例如：` hasRole`(),`login()`等方法

2. Realm方法，是用来认证和授权的方法，shiro默认提供了很多realm的实现方法，可以参考`JdbcRealm`（数据库验证） `IniRealm` （读配置验证）

3. 一般我们需要来自定义realm方法只需要根据需要继承现有的realm方法，例如shiro提供的抽象类：`AuthorizingRealm` ,实现`doGetAuthenticationInfo` 方法完成认证，实现`doGetAuthorizationInfo` 完成授权即可

4. shiro的密码认证用的是`CredentialsMatcher`，通过比对token和info里面的密码来完成认证

5. `CredentialsMatcher`类在shiro中提供了多种实现，默认用的是`SimpleCredentialsMatcher`这个是用明文比对，一般不用。用的较多的是加密实现类`HashedCredentialsMatcher`,这里可以指定加密方法，加密次数，盐（为保证同一密码在数据库中看到的加密结果不一致，一般用代表唯一性的值，例如userid）

   ```java
   public class HashedCredentialsMatcher extends SimpleCredentialsMatcher {
   
       /**
        * @since 1.1
        */
       //加密名称 如：MD5
       private String hashAlgorithm;
       //加密次数
       private int hashIterations;
       //默认在info中传了salt值就会为true，不用配置
       private boolean hashSalted;
       //默认true
       private boolean storedCredentialsHexEncoded;
   
   ```

6. `token`是把前台获取的用户名密码封装成的对象，常用的为`UsernamePasswordToken`。里面可以调用获取用户名，密码（认证值），记住我（使用cookie的方式免登陆）
7. `info`结尾的类就是shiro里面配置的用户信息，可以从数据库来也可以从ini配置文件里面读取，常用的info类为认证类`SimpleAuthenticationInfo`（存放用户信息）和授权类`SimpleAuthorizationInfo`（存放角色信息）
8. **securityManager**类似安全管理者，这里主要是用来调用login()方法来返回shiro的subject对象。主要用到的实现类为`DefaultWebSecurityManager`（web应用的管理者）,要想shiro的配置生效，必须指定**securityManager**。



###  认证

>  认证类似系统中的登录操作，只不过是shiro有多种认证策略，也可以自定义认证策略，只需要继承或实现现有的realm类

1. 登录的核心代码

```java
//获取当前的subject
Subject su = SecurityUtils.getSubject();
//根据前台的用户名密码封装成UsernamePasswordToken
UsernamePasswordToken token = new UsernamePasswordToken(username,password);
//调用login方法去验证用户名和密码来返回状态
su.login(token);
```

2. login的源码在`DelegatingSubject`

```java
public void login(AuthenticationToken token) throws AuthenticationException {
        clearRunAsIdentitiesInternal();
    	/**
    	1. 核心代码在这里，subject对象是调用securityManager获取的，这里的		securityManager需要在项目配置拦截器的时候指定好
    	**/
        Subject subject = securityManager.login(this, token);

        PrincipalCollection principals;

        String host = null;

        if (subject instanceof DelegatingSubject) {
            DelegatingSubject delegating = (DelegatingSubject) subject;
            //we have to do this in case there are assumed identities - we don't want to lose the 'real' principals:
            principals = delegating.principals;
            host = delegating.host;
```

3. 查看`DefaultWebSecurityManager`里面的login方法

```java
public Subject login(Subject subject, AuthenticationToken token) throws AuthenticationException {
        AuthenticationInfo info;
        try {
            // 根据token获取对应的验证info
            info = authenticate(token);
        } catch (AuthenticationException ae) {
            try {
                onFailedLogin(token, ae, subject);
            } catch (Exception e) {
                if (log.isInfoEnabled()) {
                    log.info("onFailedLogin method threw an " +
                            "exception.  Logging and propagating original AuthenticationException.", e);
                }
            }
            throw ae; //propagate
        }
		
    	//设置SubjectContext，subject上下文
        Subject loggedIn = createSubject(token, info, subject);
		
    	//完成登录，判断是否勾选rememberme，往cookie里面加上时效
        onSuccessfulLogin(token, info, loggedIn);

        return loggedIn;
    }
```

4. 主要看如何获取`AuthenticationInfo`的

```java
    protected AuthenticationInfo doAuthenticate(AuthenticationToken authenticationToken) throws AuthenticationException {
        assertRealmsConfigured();
        //获取shiro中配置的realm
        Collection<Realm> realms = getRealms();
        if (realms.size() == 1) {
            //一个
            //在这里对密码进行比对
            return doSingleRealmAuthentication(realms.iterator().next(), authenticationToken);
        } else {
            //多个
            return doMultiRealmAuthentication(realms, authenticationToken);
        }
    }
```

5. shiro中密码的比对规则

```java
//1.过去info 
public final AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

        AuthenticationInfo info = getCachedAuthenticationInfo(token);
        if (info == null) {
            //otherwise not cached, perform the lookup:
            info = doGetAuthenticationInfo(token);
            log.debug("Looked up AuthenticationInfo [{}] from doGetAuthenticationInfo", info);
            if (token != null && info != null) {
                //冲缓存里面取
                cacheAuthenticationInfoIfPossible(token, info);
            }
        } else {
            log.debug("Using cached authentication info [{}] to perform credentials matching.", info);
        }

        if (info != null) {
            //验证密码的代码
            assertCredentialsMatch(token, info);
        } else {
            log.debug("No AuthenticationInfo found for submitted AuthenticationToken [{}].  Returning null.", token);
        }

        return info;
    }


//2.验证密码的代码
 protected void assertCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) throws AuthenticationException {
    	 //获取密码验证器
        CredentialsMatcher cm = getCredentialsMatcher();
        if (cm != null) {
            //验证token和info的密码是否相同
            if (!cm.doCredentialsMatch(token, info)) {
                //not successful - throw an exception to indicate this:
                String msg = "Submitted credentials for token [" + token + "] did not match the expected credentials.";
                throw new IncorrectCredentialsException(msg);
            }
            
            
            
//3.当前类的构造里面指定了默认的密码验证器
            
    public AuthenticatingRealm() {
        //构造器初始化的是简单密码验证器
        this(null, new SimpleCredentialsMatcher());
    }
```

### shiro的所有过滤器

| Filter Name       | Class                                                        |
| :---------------- | :----------------------------------------------------------- |
| anon              | [org.apache.shiro.web.filter.authc.AnonymousFilter](http://shiro.apache.org/static/current/apidocs/org/apache/shiro/web/filter/authc/AnonymousFilter.html) |
| authc             | [org.apache.shiro.web.filter.authc.FormAuthenticationFilter](http://shiro.apache.org/static/current/apidocs/org/apache/shiro/web/filter/authc/FormAuthenticationFilter.html) |
| authcBasic        | [org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter](http://shiro.apache.org/static/current/apidocs/org/apache/shiro/web/filter/authc/BasicHttpAuthenticationFilter.html) |
| logout            | [org.apache.shiro.web.filter.authc.LogoutFilter](http://shiro.apache.org/static/current/apidocs/org/apache/shiro/web/filter/authc/LogoutFilter.html) |
| noSessionCreation | [org.apache.shiro.web.filter.session.NoSessionCreationFilter](http://shiro.apache.org/static/current/apidocs/org/apache/shiro/web/filter/session/NoSessionCreationFilter.html) |
| perms             | [org.apache.shiro.web.filter.authz.PermissionsAuthorizationFilter](http://shiro.apache.org/static/current/apidocs/org/apache/shiro/web/filter/authz/PermissionsAuthorizationFilter.html) |
| port              | [org.apache.shiro.web.filter.authz.PortFilter](http://shiro.apache.org/static/current/apidocs/org/apache/shiro/web/filter/authz/PortFilter.html) |
| rest              | [org.apache.shiro.web.filter.authz.HttpMethodPermissionFilter](http://shiro.apache.org/static/current/apidocs/org/apache/shiro/web/filter/authz/HttpMethodPermissionFilter.html) |
| roles             | [org.apache.shiro.web.filter.authz.RolesAuthorizationFilter](http://shiro.apache.org/static/current/apidocs/org/apache/shiro/web/filter/authz/RolesAuthorizationFilter.html) |
| ssl               | [org.apache.shiro.web.filter.authz.SslFilter](http://shiro.apache.org/static/current/apidocs/org/apache/shiro/web/filter/authz/SslFilter.html) |
| user              | [org.apache.shiro.web.filter.authc.UserFilter](http://shiro.apache.org/static/current/apidocs/org/apache/shiro/web/filter/authc/UserFilter.html) |





