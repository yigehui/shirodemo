package com.yigehui.shirodemo.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;


@Controller
public class IndexController {

    private static final Logger log = LoggerFactory.getLogger(IndexController.class);
    public String index(){
        return "index";
    }

    @RequestMapping(value = "/login",method = RequestMethod.GET)
    public ModelAndView loginPage(){
        ModelAndView mv = new ModelAndView();
        mv.addObject("test","login");
        mv.setViewName("html/login");
        return mv;
    }
    @RequestMapping(value = "/unauthorized",method = RequestMethod.GET)
    public ModelAndView unauthorized(){
        ModelAndView mv = new ModelAndView();
        mv.addObject("test","你没有权限哦");
        mv.setViewName("html/unauthorized");
        return mv;
    }
    @RequestMapping(value = "/edit",method = RequestMethod.GET)
    public ModelAndView edit(){
        ModelAndView mv = new ModelAndView();
        mv.addObject("test","编辑页面");
        mv.setViewName("html/edit");
        return mv;
    }
    @RequestMapping(value = "/login",method = RequestMethod.POST)
    public String login(String username, String password, boolean rememberme,HttpServletRequest request){
        Subject su = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(username,password);
        token.setRememberMe(rememberme);
        su.login(token);
        request.getSession().setAttribute("user",username);
        if(su.isAuthenticated()){
            return "redirect:/list";
        }
        return "login";
    }

    //@RequiresRoles("admin")
    @RequestMapping("/list")
    public ModelAndView list(){
        ModelAndView mv = new ModelAndView();
        mv.addObject("test","list");
        Subject su = SecurityUtils.getSubject();
        log.info(su.isAuthenticated()+"");
        log.info(su.isRemembered()+"");
        mv.addObject("user",su.getSession().getAttribute("user"));
        mv.setViewName("html/list");
        return mv;
    }
}
