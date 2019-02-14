## SiteServerCMS-Remote-download-Getshell-vulnerability

SiteServerCMS 远程模板下载Getshell漏洞
![avatar](https://raw.githubusercontent.com/zhaoweiho/SiteServerCMS-Remote-download-Getshell/master/img/598750731.jpg)

漏洞缺陷是由于后台模板下载位置未对用户权限进行校验，且 ajaxOtherService中的downloadUrl参数可控，导致getshell，目前经过测试发现对5.0版本包含5.0以下通杀.先调用了DecryptStringBySecretKey函数将downloadurl先进行了解密，之后调用SiteTemplateDownload函数进行模板下载并自解压。

且SecretKey在5.0是默认值
> vEnfkn16t8aeaZKG3a4Gl9UUlzf4vgqU9xwh8ZV5

### References

Author:1u0hun

From : https://www.freebuf.com/articles/web/195105.html

### Affected Version
SiteServerCMS 5.x

SiteServerCMS 4.x

### PoC
Author:We1h0@PoxTeam

python poc.py -u http://localhost
![avatar](https://raw.githubusercontent.com/zhaoweiho/SiteServerCMS-Remote-download-Getshell/master/img/494367940.jpg)

python poc.py -f url.txt

Ps:注意最后面没/

### 搜索引擎关键字:

inurl:/sitefiles/services

inurl:/sitesever/login.aspx

### 修复方案
修改 C:/WebSite/SiteFiles/Configuration/Configuration.config

secretKey的值

