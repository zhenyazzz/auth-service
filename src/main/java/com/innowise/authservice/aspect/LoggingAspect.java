package com.innowise.authservice.aspect;

import java.util.Arrays;
import java.util.stream.Collectors;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Aspect
@Component
@Slf4j
public class LoggingAspect {

    @Pointcut("within(com.innowise.authservice.service..*)")
    public void serviceLayer() {}

    @Before("serviceLayer()")
    public void logBefore(JoinPoint joinPoint) {
        String args = Arrays.stream(joinPoint.getArgs())
                .map(Object::toString)
                .collect(Collectors.joining(", "));
        
        log.debug("--> Invoke: {}. Arguments: [{}]", 
                joinPoint.getSignature().toShortString(), args);
    }

    @AfterReturning(pointcut = "serviceLayer()", returning = "result")
    public void logAfter(JoinPoint joinPoint, Object result) {
        String resultStr = result != null ? result.toString() : "void";
        log.debug("<-- Return: {}. Result: {}",
                joinPoint.getSignature().toShortString(), resultStr);
    }

    @AfterThrowing(pointcut = "serviceLayer()", throwing = "e")
    public void logAfterThrowing(JoinPoint joinPoint, Throwable e) {
        log.error("!!! Exception in {}: {}", 
                joinPoint.getSignature().toShortString(), e.getMessage());
    }

}