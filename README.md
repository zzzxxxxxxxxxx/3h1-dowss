# 3h1-dowss

基于 cf worker Durable Object 的 CF 隧道，一旦在指定的地区创建DO实例，IP 地址就稳定下来，几乎不会变，要变也变动很小(变动，可能你长时间没有使用，不活跃而自动销毁，重新连接调剂到隔壁IP)，只变IPv4最后一段数字。

## 一、关于部署

- 使用 Wrangler CLI 部署

  先将全部代码下载或git clone命令下载到本地电脑中，然后：

```
# 安装依赖
npm install

# 登录你的cloudflare账号
npx wrangler login

# 部署到cloudflare workers中
wrangler deploy
```

- 其他部署途径，没有尝试过。

## 二、修改变量

可以先部署，再到CF后台修改**变量和机密**。也可以部署前找到"wrangler.jsonc"里面 `vars`字段，修改里面的字段值。

| 名称          | 说明                                                         |
| ------------- | ------------------------------------------------------------ |
| PYIP          | 等价于PROXYIP                                                |
| UUID4         | vless协议的userId                                            |
| PASSWORD      | trojan协议的密码，可以不设置，使用vless协议的userId          |
| ENABLE_SS     | 是否开启shadowsocks协议？总电闸，设置为false就关闭它，true就是开启。 |
| ALLOWED_RULES | shadowsocks协议专属，小电闸。添加你所在公网IP或IP所在的CIDR(IP段)，cf会知道你的IP地址，不要想隐藏；只有你指定的IP地址才能使用，使用其它IP连接的禁用。支持IPv4、IPv6、IPv4 CIDR/IPv6 CIDR，默认是所有公网IP都能连接它；示例："192.168.1.100,192.168.100.0/24,2001:db8::1,2001:db8::/32"。 |
| REGION        | 第一次部署实例化才生效，重新覆盖部署无效，可选：["wnam", "enam", "sam", "weur", "eeur", "apac", "oc", "afr", "me"]，你可以试一下，部署后，不要连接，再到cf后台修改该变量值，一旦连接成功，修改它无效，可能导致网速变慢。 |

## 三、注意：

### 1、Durable Object 免费额度：

- 无服务器计算和 SQL 数据库
- 每天最多 100,000 个请求
- 每天最多 13,000 GB-秒持续时间
- 每天最多 5 百万次行读取
- 每天最多 100,000 次行写入
- 含 5GB 存储

这个要注意：特别是**每天最多 100,000 个请求** 和**每天最多 13,000 GB-秒持续时间** 。

### 2、换其他地区要注意的坑：

```
const stub = env.WS_DO.get(id, {locationHint: "wnam"});
```

locationHint 只在“第一次实例化”时被 Cloudflare 使用。之后的所有 get()（即使带不同的 hint）都忽略这个参数，只把请求路由到已经绑定好的节点。

```
const id = env.WS_DO.idFromName(name);
```

可以尝试改变name字符串，有概率变成wnam大区下面的其它城市。

还有一种方法，将DO放置到 eu (欧盟地区) 和 fedramp (好像是放置到美国本地大陆)，它优先于 locationHint。

```
const id = env.WS_DO.jurisdiction("eu").idFromName(name);
const id = env.WS_DO.jurisdiction("fedramp").idFromName(name);
```

设置了jurisdiction，后面的 locationHint 参数忽略。

最后，网速OK情况，就不要乱动，可能改得速度更慢，要删掉重新部署，还可能重新部署也慢，要等一天重新部署才恢复。

以上，经这几天测试的经验之谈，不保证就是唯一真理。

### 3、部署后，使用发现网速比较慢

开始使用是比较慢的，慢慢会提升速度，如果用了很久，速度还是没有提升，就是DO放置的位置不合适。特别是多次更改位置部署的，很大概率变慢的。

### 4、部署位置可参考： [link](https://where.durableobjects.live/)
