package com.yigehui.shirodemo.configuration;

import com.yigehui.shirodemo.realm.MyRealm;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authc.credential.SimpleCredentialsMatcher;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.mgt.RememberMeManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.text.PropertiesRealm;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.web.env.DefaultWebEnvironment;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.Cookie;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.LinkedHashMap;

@Configuration
public class ShiroConfiguration implements WebMvcConfigurer {

    private static Logger log = LoggerFactory.getLogger(ShiroConfiguration.class);


    @Bean("shiroFilter")
    public ShiroFilterFactoryBean shiroFilter(SecurityManager securityManager){
        log.info("开始配置shiro拦截器");
        ShiroFilterFactoryBean sf =  new  ShiroFilterFactoryBean() ;
        sf.setLoginUrl("/login");
        sf.setSuccessUrl("/list");
        sf.setUnauthorizedUrl("/unauthorized");
        sf.setSecurityManager(securityManager);

        LinkedHashMap<String, String> filterChainDefinitionMap = new LinkedHashMap<>();
        filterChainDefinitionMap.put("/login", "anon");
        filterChainDefinitionMap.put("/logout", "logout");
//        filterChainDefinitionMap.put("/loginUser", "anon");
//        filterChainDefinitionMap.put("/admin", "roles[admin]");//admin的url，要用角色是admin的才可以登录,对应的拦截器是RolesAuthorizationFilter
        filterChainDefinitionMap.put("/edit", "perms[edit]");//拥有edit权限的用户才有资格去访问
//        filterChainDefinitionMap.put("/druid/**", "anon");//所有的druid请求，不需要拦截，anon对应的拦截器不会进行拦截
        filterChainDefinitionMap.put("/**", "authc");//所有的路径都拦截，被UserFilter拦截，这里会判断用户有没有登陆
        sf.setFilterChainDefinitionMap(filterChainDefinitionMap);
        return sf;
    }

    @Bean("securityManager")
    public SecurityManager securityManager(Realm realm) {
        log.info("开始配置securityManager");
        DefaultWebSecurityManager dc = new DefaultWebSecurityManager();
        dc.setRealm(realm);
        CookieRememberMeManager remanger = (CookieRememberMeManager)dc.getRememberMeManager();
        Cookie cookie =remanger.getCookie();
        cookie.setMaxAge(20);
        remanger.setCookie(cookie);
        dc.setRememberMeManager(remanger);
        return dc;
    }

    @Bean("realm")
    public MyRealm myRealm(CredentialsMatcher credentialsMatcher ){
        log.info("配置自定义realm,用来授权和认证");
        MyRealm myrealm = new MyRealm();
        myrealm.setCredentialsMatcher(credentialsMatcher);
        return myrealm;
    }

    @Bean("credentialsMatcher")
    public HashedCredentialsMatcher hashedCredentialsMatcher(){
        log.info("配置默认加密算法");
        HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
        //加密名称
        hashedCredentialsMatcher.setHashAlgorithmName("MD5");
        //加密次数
        hashedCredentialsMatcher.setHashIterations(10);
        //这里不需要设置盐，shiro会根据info中是否存在盐值来自动设置
        //hashedCredentialsMatcher.setHashSalted(true);
        return hashedCredentialsMatcher;
    }

    /*
    * 开启shiro的注解，需要注入两个类
    * 这下面的3个bean是为了使用shiro注解的配置，根据官网提供的例子配置的
    <bean class="org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator" depends-on="lifecycleBeanPostProcessor"/>
    <bean class="org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor">
    <property name="securityManager" ref="securityManager"/>
    </bean>
    *
    *
    * */
    @DependsOn("lifecycleBeanPostProcessor")
    @Bean
    public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator(){
        return new DefaultAdvisorAutoProxyCreator();
    }
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager){
        AuthorizationAttributeSourceAdvisor az = new AuthorizationAttributeSourceAdvisor();
        az.setSecurityManager(securityManager);
        return az;
    }
    //<bean id="lifecycleBeanPostProcessor" class="org.apache.shiro.spring.LifecycleBeanPostProcessor"/>
    @Bean
    public LifecycleBeanPostProcessor lifecycleBeanPostProcessor(){
        return new LifecycleBeanPostProcessor();
    }



    public static void main(String[] args) {
        SimpleHash sh = new SimpleHash("MD5","user","user",10);
        System.out.printf(sh.toString());
    }
}
