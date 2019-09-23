package com.yigehui.shirodemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication(scanBasePackages = "com.yigehui.shirodemo")
public class ShirodemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(ShirodemoApplication.class, args);
    }

}
