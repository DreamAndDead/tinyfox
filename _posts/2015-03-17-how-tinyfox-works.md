---
layout: post
category: tinyfox
tags: 校园网认证 EAP EAPOL 网络
title: How Tinyfox Works
---
[tinyfox](https://github.com/DreamAndDead/tinyfox)是一个基于802.1x原理实现的一个[校园网认证客户端](https://github.com/DreamAndDead/tinyfox)，校园网认证基于802.1X认证系统，此系统使用EAP协议交换信息，其信息交换的一套规则正是实现认证客户端的原理

## Brief introduction to 802.1x

802.1x是典型的Client/Server结构，包括三个实体


![802.1x client server](/images/802.1x client server.png)
客户端，设备端，认证服务器

- 客户端可以理解为我们在PC上运行的软件如锐捷，发起认证
- 设备端可以理解为我们通过网线连接到墙上的端口，隐藏在墙后面的东西，是我们与认证服务器交流的信使
- 认证服务器，学校真正用来控制我们上网节奏的管理者

## Flow 
我们不能直接与服务器交流，只能与其中介设备端来通信，因此设备端与服务器的交流就不是我们关心的重点，我们只需要把注意力放在设备端就好

遗憾的是设备端并不是一个热爱交流的人，它只能识别极少部分的数据包，其它的则不理睬，如一个木枘的守门人

与守门人交流，我们先要了解其独特的协议EAP，EAPOL，这是我们和它的共同语言

然后就可以拿着刺探的情报图，来穿过这道阻隔我们连接网络的门了


![802.1x flow](/images/802.1x flow.png)

1. EAPOL-start 认证的开始由我们发起，这是一个目的MAC地址固定的广播报文，使设备端注意到我们
2. EAP-Request/Identity 设备端注意到我们之后，让我们出示我们的上网帐号
3. EAP-Response/Identity 嗯就告诉它我们的帐号就好了
4. 设备端告诉服务器我们的身份
5. 身份没有问题之后，服务器发送过来MD5校验的加密字
6. EAP-Request/MD5 challenge 这个比较有意思，设备端与服务器交流之后，服务器是知道我们的密码的，它自身随机生成了一个加密字，然后和我们的密码混在一起，做了一个MD5运算，生成了一个暂时的数，就像是临临时在纸上写一个数字一样来难为我们，所谓的MD5
challenge即是相当于把那个加密字告诉我们，如果我们没有密码，即使我们用了MD5运算，也是不能生成和它一样的数字的
7. EAP-Response/MD5 challenge 嗯如它所愿，我们运算就按照它的要求来吧，运算出一个数字来给它看
8. 设备端代为传送我们自己运算过后的结果
9. 服务器将其值与自身的值对比，发送过来认证成功的消息
10. EAP-Success 设备端允许我们通过那扇门了
11. 端口被授权 即我们就可以使用网络资源了
12. 握手定时器 在我们成功进门之后，还要时不时的告诉它，我还在这里，定时器的话就是我们至少对它时不时联系的一个间隔
13. 这里的话还有点不确定，如图的话是设备端会时不时的请求我们验证身份，来确定我们是否还在，但是我也看到过另一个版本是由客户端主动的向设备端时不时的发送数据包（也称心跳包）来告诉它自己还在使用网络不至于被关闭连接，关于这里的话后面还有一个比较有意思的我之后再说
14. EAPOL-Logoff 对设备端说我们要下线了，不过根据我的经验的话，应该很少人用这个功能的，除非是校园网一时抽风，我们就在下面尝试上线又下线又上线....
15. 端口非授权 这也是我们端口的默认状态，处于一个非连接的状态，除非我们goto 1. EAPOL-start

## EAP & EAPOL
前面谈到，EAP与EAPOL是我们与设备端交流之前必须写学会的语言规则，即数据包的规则

## EAP Packet 
<table border="1">
    <tr>
        <th>Code</th>
        <th>Identifier</th>
        <th>Length</th>
        <th>Data</th>
    </tr>
    <tr>
        <td>1 byte</td>
        <td>1 byte</td>
        <td>2 bytes</td>
        <td>variable length</td>
    </tr>
</table>
<br>

#### Code field
Code字段定义此数据包的类型，如下

<table border="1">
    <tr>
        <th>Code</th>
        <th>Description</th>
    </tr>
    <tr>
        <td>1</td>
        <td>Request</td>
    </tr>
    <tr>
        <td>2</td>
        <td>Response</td>
    </tr>
    <tr>
        <td>3</td>
        <td>Success</td>
    </tr>
    <tr>
        <td>4</td>
        <td>Failure</td>
    </tr>
    <tr>
        <td>5</td>
        <td>Initiate</td>
    </tr>
    <tr>
        <td>6</td>
        <td>Finish</td>
    </tr>
</table>
<br>

看到上面的Request，Success是不是很眼熟呢

#### Identifier field
这个Id字段是很有用的，作为数据包的一个标识，用来匹配Request与Response使其对应，如Id==1的Response一定是针对Id==1的Request的回复

*更重要的是*，它自身也参与MD5 chanllenge的运算

#### Length field
标识了整个数据包的长度，`<<Code-------------------Data>>`

#### Data field
EAP数据包携带的数据，由Code的不同会有不同的解释

## More details
这里详细的说明不同的行为下，数据包的异同

#### Request & Response Packet Format
数据包的总体结构与上面是相同的，不同之处在于对于Data部分的解读

<table border="1">
<thead>
<tr>
 <th style="text-align:center;">Code</th>
 <th style="text-align:center;">Identifier</th>
 <th style="text-align:center;">Length</th>
 <th style="text-align:center;">Type</th>
 <th style="text-align:center;">Type-Data</th>
</tr>
</thead>
<tbody><tr>
 <td style="text-align:center;">1 byte</td>
 <td style="text-align:center;">1 byte</td>
 <td style="text-align:center;">2 bytes</td>
 <td style="text-align:center;">1 byte</td>
 <td style="text-align:center;">variable length</td>
</tr>
</tbody></table>
<br>

再提一下，Code field的值决定了包的类型，在此处则分辨数据包为Request or Response

Type的定义有达50+种不同类型，这里我们只关心其中的两个

<table border="1">
<thead>
<tr>
 <th style="text-align:center;">Type</th>
 <th style="text-align:center;">Description</th>
</tr>
</thead>
<tbody><tr>
 <td style="text-align:center;">1</td>
 <td style="text-align:center;">Identify</td>
</tr>
<tr>
 <td style="text-align:center;">4</td>
 <td style="text-align:center;">MD5-Chanllege</td>
</tr>
</tbody></table>
<br>

组合起来是不是觉得眼熟呢

类似的，Type Data也由Type的值来进行不同的解释

#### Success & Failure Packet Format
包的结构没有变化，关键在于对Data数据的解读方面，Data方面携带了服务器传送过来的信息

举例来说如果成功，则其信息就是一些学校发过来的小广告，如第N期科学精神讲座什么的

如果失败，则可能是余额不足之类的

## EAPoL Frame Format
EAPoL即EAP over LAN，其只是在EAP的基础上进行了一层封装，使其可以在多种网络环境下传输比如以太网

<table border="1">
<thead>
<tr>
 <th style="text-align:center;">Mac Header</th>
 <th style="text-align:center;">Ethernet Type</th>
 <th style="text-align:center;">Version</th>
 <th style="text-align:center;">Packet Type</th>
 <th style="text-align:center;">Packet Body Length</th>
 <th style="text-align:center;">Packet Body</th>
 <th style="text-align:center;">Frame Check Sequence</th>
</tr>
</thead>
<tbody><tr>
 <td style="text-align:center;">12 bytes</td>
 <td style="text-align:center;">2 bytes</td>
 <td style="text-align:center;">1 bytes</td>
 <td style="text-align:center;">1 bytes</td>
 <td style="text-align:center;">2 bytes</td>
 <td style="text-align:center;">variable length</td>
 <td style="text-align:center;">4 bytes</td>
</tr>
</tbody></table>
<br>

看到Mac Header与Ethernet Type，是不是很熟悉呢

#### Mac Header
前6字节是目的地址，后6字节为源地址

#### Ethernet Type
0x88 0x8e，标识了EAPoL的类型

#### Version
学校里的好像还是Version 1吧

#### Packet Type
其定义有5种不同的值，这里我们只关心其中的3种

<table border="1">
<thead>
<tr>
 <th style="text-align:center;">Packet Type</th>
 <th style="text-align:center;">name</th>
 <th style="text-align:center;">description</th>
</tr>
</thead>
<tbody><tr>
 <td style="text-align:center;">0x00</td>
 <td style="text-align:center;">EAP-Packet</td>
 <td style="text-align:center;">携带着一个EAP数据包</td>
</tr>
<tr>
 <td style="text-align:center;">0x01</td>
 <td style="text-align:center;">EAPoL-Start</td>
 <td style="text-align:center;">认证的开始</td>
</tr>
<tr>
 <td style="text-align:center;">0x02</td>
 <td style="text-align:center;">EAPoL-Logoff</td>
 <td style="text-align:center;">下线退出</td>
</tr>
</tbody></table>
<br>

#### Packet Body Length
指Packet Body的长度，此处切记不是整个包的长度

如果其值为0，则说明没有Packet Body

#### Packet Body
EAPoL所携带的内容，举例来说如果Packet Type == 0x00，则此数据包为一个完整的EAP协议包（如上面介绍的）

#### Frame Check Sequence
这是一个使用校验和来检验有无错误的一个字段，据我的了解在学校里的认证这个字段没有什么作用

## Detailed Flow
有了上面的基础之后，我们再回过头来仔细的分析一下认证的过程

这里有一点特别容易混淆，需要特别的说明一下，我们与设备端传输的数据包都是EAPoL协议的数据包，EAPoL使得我们的数据包可以在以太网传输

EAPoL我们只关心它的三种类型EAPoL-Start，EAPoL-Logoff，EAP-Packet，对应到图中的话

EAPoL-Start -----> 1

EAPoL-Logoff ------> 14

EAP-Packet  -------> 2，3，6，7，10

换言之，我们进行*开始认证*与*下线退出*这两个操作的时候，与EAP协议是没有关系的

EAP协议被解读当且仅当EAPoL的包类型为EAP-Packet的时候，也只有在这时，EAPoL的Packet Body为一个完整的EAP协议包，方可用EAP协议来解读 

![802.1x flow](/images/802.1x flow 2.png)

下面我们从实际的数据包结合上面的协议进行分析（抓包分析工具使用的是wireshark）

*1* EAPoL-Start
![start](/images/start.png)
我将不同的字段用不同的颜色加以区分，整体是一个在以太网传输的EAPoL协议的数据包，由于这是第一个，我们逐个字段来看

01 d0 f8 00 00 03：目的Mac，这个地址很有意思，在EAPoL-Start中，这是一个定值，并不是我们要通信的设备端的地址，是在我们发出这个包之后，设备端根据我们的Mac，来主动联系我们

20 1a 06 5c 2d f8：我们的本机Mac

88 8e：此包为EAPoL类型

01：version 1
01：标识此包为Start，而非Logoff or EAP-Packet

00 00：数据包的长度为0，这里的0是指其携带的Data部分的内容，值为0则说明没有数据内容，本身只携带了一个Start信息，并不需要其它的数据了

可能有人问了后面不是还有那么多字节的信息吗，那些只是为了以太网下为了拼凑包的长度而添加的乱七八糟的值，对我们来说没有任何意义，下面还有很多情况是与之类似的

*2* EAP-Request Identity
![request id](/images/requestid.png)

这里我们再逐个分析下

第一行

20 1a 06 5c 2d f8：我们的本机Mac，说明设备端找到了我们，向我们发送了信息

00 1a a9 17 ff ff ：设备端的Mac，与上面EAPoL-Start对比是不是不一样，这才是设备端真正的Mac

88 8e：同上

01：同上 

00：这里就是重点了，标识此包为EAP-Packet，说明其携带了EAP数据包，有其它的信息

第二行

00 05：长度，说明EAP-Packet的长度只为5字节，即后面的 01 01 00 05 01

针对 01 01 00 05 01

01：Code == Request

01：Id == 1 标识此包的一个序号，后面的Response的Id也要为1与此Request匹配

00 05：与前面的长度值相同是一个值，在后面的包也是一样

01：Type == Identity，类型为Identity，与Code相结合即 Request Identity

到此长度已经足够5字节，说明没有其它的信息

后面的其它字节就如同前面所说的一样是没有用的信息我们不用在意

*3* EAP-Response Identity
![response id](/images/responseid.png)

第一行与2的第一行分析相同 

第二行也类似，我们单独拿出来看一下

00 0f：EAP-Packet的长度

02：Code == Response

01：Id == 1，针对前面的Request == 1的回复

00 0f：长度值，与上相同 

01：Type == Identity

到这里才只有5个字节，而总长度为0x0f == 15字节，后面的10字节即其携带的内容，即我们的帐号

55 32 30 31 31 31 37 37 33 35：认证的帐号

剩下的内容没有意义

*4* EAP-Request MD5 challenge
![request md5](/images/requestmd5.png)

和前面的相同，不过原来的信息变化了而已，我们就从变化的那些地方来看

第二行近中间开始

04：Type == MD5 Chanllenge

剩下的内容为Data的解析部分，这里的话对于MD5 Chanllenge是这样解读的

10：MD5 Value Size，给予的MD5加密字的长度

94 4f d2 ........44 47 83：MD5 Value，后期我们即使用此数据包的Id，MD5 Value与我们的密码做MD5运算，得到一个16字节的值，返回回去，即下一个包的内容 

*5* EAP-Response MD5 challenge
![response md5](/images/responsemd5.png)

与上一个包的分析很相同，不过这里EAP-Packet的长度为32字节

我们可以看到后16+10字节是我们根据MD5运算后的Value+帐号

*6* Succcess
![success](/images/success.png)

我们认证成功之后，服务器发来贺电

这个包的长度有500字节，这里的冗余信息还是有用的，即学校给我们发来的小广告

*7* EAPoL-Logoff
![logoff](/images/logoff.png)

第一行最后面的02所标识

*8* Failure
![failure](/images/failure.png)

从EAP协议来分析，在长度为0x0a的数据包中，最后剩下的00 00 13 11 00 00还没有解读过是什么意思，起码前面的信息告诉我们，我们认证失败了


## In the end
至此，我们对整个的认证流程应该有一个直观的了解了，相信大家也可以很轻松的写出一个认证工具来而不是像rj一样40+MB的庞然大物

## ps
上面说了很多，其实还有不少遗漏的地方可能大家已经注意到了

1. DHCP，现在学校都已经是动态IP获取了，获得IP的这个过程在哪里，其实在我自己做实验的时候，在Linux上开启dhcpd服务的情况下进行的试验，可能这个部分由它帮我们做好了

2. 心跳包，实话说我并没有抓取到任何关于心跳包的内容

3. 无线wifi hustwireless的认证，用EAPol的方法好像没有用

3. 二次认证，其实我不清楚为什么需要两次，不过在自己从rj运行抓包的情况来看，实际是这样的（我先下线再上线的）
![flow](/images/realsituation.png)
确实有两次的认证，而且包的内容完全一样，而且如果细心的话，用dhcp做关键字来过滤，你会发现有DHCP Protocol（由wireshark来看）的数据包在两次认证之间

真实的过程与自己所写的[tinyfox](https://github.com/DreamAndDead/tinyfox)工具差别如此之大，这也是我说它可以奇迹般运行的原因了
