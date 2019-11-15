<p align="center">
 终端远程验证方案
</p>
为对各类终端设备进行身份认证、远程度量、版本升级，确保终端可信接入，同时满足前期《远程验证细化方案》当中对于终端侧与服务侧交互内容的定义，本方案对接入安全管理平台的终端设备功能配置进行设计，从启动度量、身份认证过程阐述具体流程。

![total](https://github.com/wilber1989/termverify/blob/master/examples/total.png)

	（1）身份认证
a、终端调用RSA函数生成设备公私钥对（dpubkey、dprikey），密钥对以只读方式储存在本地flash当中，并予以权限控制；
b、使用由安全管理平台提供的产品私钥（pprikey）对设备ID及设备公钥e和n值进行签名，以json格式组织数据，如下：
payload = {
    'flag':'register',
    'deviceid':'chislab1'
    'pub_e':'xx',
    'pub_n':'xx',
    'sign':'xxx'
}
c、利用MQTT协议将主题为“devices/TC/measurement”、flag为register的数据publish至broker服务器，等待安全管理平台订阅消费；
发送函数形式如下：
mqtt_publish(&client, topic, json, strlen((const char *)json)+1, MQTT_PUBLISH_QOS_0);
d、等待接受服务器端验证返回结果，订阅broker侧相同主题的保留消息（即最后一条发布消息），获取到后判断flag=register_res，利用安全管理平台公钥对数据进行验签，并判断返回json当中key=status的键值是否为success。
订阅函数形式如下：
mqtt_subscribe(&client, topic, MQTT_PUBLISH_QOS_1 | MQTT_PUBLISH_RETAIN);
![total](https://github.com/wilber1989/termverify/blob/master/examples/register.png)

（2）远程度量
a、若验签及设备注册success，设备读取BIOS及OS镜像img文件，并求出SHA度量值，按顺序对镜像hash值进行PCR寄存器扩展储存；
b、利用设备私钥（dprikey）对镜像文件PCR度量值进行签名，json组包格式如下所示：
payload = {
 'flag':'measure'
'deviceid':'chislab1'
 "ML": { 
"length": 2,
 "1": {
 "name": "BIOS", 
"sha1": "xxxxxxxx",
 "pcr": 1, 
}, 
"2": { 
"name": "OS",
"sha1": "xxxxxxxx", 
"pcr": 1, 
} 
}, 
"PCRS": { 
"1": "xxxxxxxxx"
 }, 
"sign": "xxxxxxxxx" 
}
以上流程图示如下：
![total](https://github.com/wilber1989/termverify/blob/master/examples/measurement.png)

c、将主题为“devices/TC/measurement”、flag为measure的数据的json数据发送至broker服务器，等待安全管理平台进行度量验证。
d、订阅相同主题消息，等待并获取到后判断flag=measure_res，利用安全管理平台公钥对数据进行验签，并判断返回json当中key=status的键值是否为success。
（3）版本升级
a、若验签及设备注册success，订阅主题为“devices/TC/update”的消息，在获取到消息后利用安全管理平台公钥对数据进行验签，数据格式如下：
payload = {
    'flag':'update',
    'deviceid':'chislab1'
    'version':'xx',
    'download':'xx',
    'sign':'xxx'
}
b、获取本地固件version，并与获取到的最新远程version进行判断，若版本一致，则不予更新，用设备私钥（dprikey）签名后发送反馈消息，格式如下：
payload = {
    'flag':'update_res',
    'status':'xxx'
'sign':'xxxx'
}
c、若版本不一致，按照download地址下载并安装固件，重启更新系统固件镜像和固件版本信息。固件更新成功后，发送主题为“devices/TC/update”的消息，消息格式与b相同，通知安全管理平台更新完毕。


