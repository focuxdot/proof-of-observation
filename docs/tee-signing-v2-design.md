# TEE 签名载荷 v2 —— 自证内容(字段分解版 · 设计定稿)

> ⚠️ **规范地位:本文是设计 rationale(为什么这么分字段),非规范文本。**
> 规范以 [`proof-of-observation-protocol-v1.md`](proof-of-observation-protocol-v1.md)(RFC2119,实现无关)为准;
> 字节布局/验证流程一旦与本文有出入,**以英文规范为准**。本文保留设计动机与取舍论证,便于查阅。

> **状态:当前 v2 规范。** 签名域为 `tee-exchange-v2`;v1(monolithic `H(canon_req)`,
> 域 `tee-relay-v1`)不在当前实现中使用。v2 从**用户验证**角度重做:
> **不再把异构字段揉成一个哈希**,改为**按用户能独立核对的最小粒度分字段签**。
>
> 沿革:本版取代早先的「v2 = canon_req + 可还原 servername」草案 —— 那版招牌字段 servername 与 canon_req.host
> 冗余、还得靠 preimage 打补丁。字段分解后**两个问题都消失**(host 就是一个可还原字段;preimage 不再需要)。详见 §11。

---

## 0. 设计原则:按「用户能独立核对的最小粒度」签

> **每一项用户会单独判断的事,就单独签一个字段** —— 该读的明文签发,该比的各自哈希,一个签名把它们绑在一起。
> **不要把它们预先揉成一个哈希。**

v1 的硬伤就是 `canon_req = method‖host‖path‖headers‖H(body)` 只签一个 `H(canon_req)`:
1. **把用户分开关心的东西强行耦合** → 想验任何一项(host / prompt)必须**重建全部**;
2. **拖进用户不知道的数据**(relay 加的 headers)→ 哪怕用户知道 host、知道自己 prompt,也因缺 headers 而整条验不了。

分字段签后,绑定不丢(都在同一个签名下),但**每项都能只用手头已有的数据单独验**:
- **该读的事实**(host / path / status)→ 明文可还原,用户直接 READ;
- **内容**(请求体 / 响应体)→ 各自独立哈希,用户各自 CHECK;
- **headers** → 用户无从判断、也不该判断的 relay 元数据 → **完全不进自证**(见 §7)。

---

## 1. 用户关心什么(自证要回答的)

| 关心 | 含义 | 靠哪个字段 |
|---|---|---|
| ① 未篡改 | 答案是模型逐字原文,中转没动过 | `response_body_sha256` |
| ② 来源 / 没掉包 | 真发去**官方端点**、用我点的模型 | `upstream_host` + 响应里的 model |
| ③ 是我的请求 | 回应对应我那条原始 prompt(没被改/注入) | `request_body_sha256` |
| ④ 新鲜 | 不是旧响应重放 | `nonce` 绑 attestation + 证书有效期 |
| —(不保) | **机密性**:不承诺;proof 不携带正文 | 正文只签哈希 |

---

## 2. 签名载荷字段(Ed25519 盖这一份声明)

| # | 字段 | 形态 | 类别 | 关心 | 含义 |
|---|---|---|---|---|---|
| 0 | `domain = "tee-exchange-v2"` | 明文常量 | 前导 | 防跨协议/换版 | 固定串 |
| 1 | `nonce` | 明文 b64 | 新鲜锚 | ④ | relay 生成,**同值嵌入 attestation 的 `nonce` 字段**(非 user_data;验证方核 `doc.nonce==proof.nonce`) |
| 2 | `upstream_host` | **明文·可还原** | 路由/来源 | ② | 飞地**实连 + 校验证书所用的名字**(读) |
| 3 | `upstream_path` | **明文·可还原** | 路由 | ②/读 | 上游 API path **(只取 `?` 之前的路径,不含 query string)**,如 `/v1/messages` |
| 4 | `http_method` | **明文·可还原** | 路由 | 读 | `POST` |
| 5 | `http_status` | **明文·可还原** | 响应元数据 | ①/读 | `200` |
| 6 | `resp_content_type` | **明文·可还原** | 响应元数据 | 读 | `text/event-stream` |
| 7 | `request_body_sha256` | 哈希 hex | 内容绑定 | ③ | `H(请求体)` —— 用户用**自己发的 body** 比 |
| 8 | `response_body_sha256` | 哈希 hex | 内容绑定 | ① | `H(响应体)` —— 用户用**收到的字节**比 |

**所有字段在同一个 Ed25519 签名下** → 绑定关系("这条 body 发去了这个 host、得到这个响应")完整保留,只是不再预先揉成一个哈希。

**没有 `request_headers_sha256`**:headers 完全不进自证(§7)。

---

## 3. body 直接哈希、结构字段明文 —— 不再有 `canonical_request`

- **请求体 / 响应体是不透明字节块** → 直接 `sha256(原始字节)`,**无需任何规范化**(用户手里就是那些字节:自己发的 body、收到的响应)。
- **结构/路由字段**(host/path/method/status/content-type)→ **明文可还原签发**,用户直接读,不必重建、不必规范化。
- 因此 v1 的 `canonical_request`(连同它的 header 排序规范化)**整个消失**。**唯一**还需要逐字节对齐的,是**声明本身的布局**(§4)—— 那是我们自控的固定结构,不含 relay/上游可塞的可变集合,对齐面比 v1 小得多。

---

## 4. 规范化字节布局(飞地签 / 验证方重组,逐字节对齐)

```
tee-exchange-v2\n
nonce=<base64>\n
upstream-host=<host>\n
upstream-path=<path · 只取 ? 之前>\n
http-method=<METHOD>\n
http-status=<十进制>\n
resp-content-type=<token>\n
request-body-sha256=<hex>\n
response-body-sha256=<hex>\n
```
- 仅 UTF-8 + `\n`(0x0A);**所有可还原字段禁含 CR/LF**(沿用现有「入站拒 CR/LF」硬化)。
  host/method/content-type 是 token、status 是整数、两个 body 哈希定长 hex、nonce 是 b64;**`upstream-path`
  只取 `?` 之前的路径**(query string 丢弃,见 §7/§9)。解析按**首个 `=`** 切 label/value(容 content-type 的
  `; charset=utf-8` 等含 `=` 的值)→ 注入安全。
- Ed25519 对**整块字节**签名。(想更稳可改每字段长度前缀的二进制,二选一;文本便于审计。)

---

## 5. proof wire v2(带外下发)

```json
{
  "v": 2, "alg": "ed25519", "public_key": "<b64 SPKI>",
  "nonce": "<b64>",
  "upstream_host": "api.example.com",
  "upstream_path": "/v1/messages",
  "http_method": "POST",
  "http_status": 200,
  "resp_content_type": "text/event-stream",
  "request_body_sha256": "<hex>",
  "response_body_sha256": "<hex>",
  "signature": "<b64 ed25519>",
  "attestation": "<b64 COSE_Sign1>",
  "pcr0": "<hex>"
}
```
`nonce`…`response_body_sha256` 按 §4 顺序**就是签名载荷**,原样带出供读取 + 重组验签;其余是信封。

---

## 6. 验证方核验(每项只用手头已有的,无需重建未知数据)

| 用户关心 | 怎么验 |
|---|---|
| 去了官方端点 / 哪个 API | **读** `upstream_host` / `upstream_path` / `http_method`(已被签名覆盖,验签过即可信) |
| 答的是我的 prompt、没被改 | `H(我发的 body) == request_body_sha256` |
| 答案未篡改 | `H(我收到的字节) == response_body_sha256` |
| 真飞地 + 审计镜像 | attestation 链到 AWS 根 + `PCR0 == 审计值` + `public_key == attestation 背书` |
| 新鲜 | `nonce == attestation.nonce` + **证书有效期**(过期 → 软提示,真实性不受影响) |
| (展示) model | 从**已验真的响应体**解析(host 验真 + 响应完整 → 响应自报 model 即权威),**无需单独签** |

步骤:重组 §4 字节块 → `Ed25519.verify(public_key, 块, signature)` → 再做上表各项。**全程不需要 relay 的 headers、不需要猜 path、不需要 preimage。**

---

## 7. 刻意不签的(同样是「合理内容」)

- **headers(请求头)**:**完全不进自证** —— 飞地不签、proof 不带、不进任何用户/审计核验路径。
  relay/飞地仍会向上游发**协议必需的头**(content-type、协议版本头、注入的 auth)让请求能跑,但**这些头不被签名、不外露**,在自证里**不留痕**。理由:headers 是 relay 元数据,用户没有参照、无从判断,签了也帮不了用户验证(残余风险见 §9)。
- **prompt / 响应明文**:proof 只携带哈希、不携带正文;不承诺机密性,父实例/relay 仍可能短暂经手明文(见 [`TEE.md`](TEE.md) §2)。
- **注入的 Authorization / api-key**:永远排除。
- **飞地自报的时钟**:不可信 → 新鲜性一律挂 attestation 的 AWS 时间戳/短命证书,**不自签 timestamp**。
- **实际拨号 IP / host:port**:**不签**(暴露上游 IP/区域、每请求变动、加噪);只签校验通过的 **host(名字)**。

---

## 8. `upstream_host` 的暴露分析(结论)

- 真正暴露上游身份的是 **`upstream_host`(#2)**,而那是**有意展示**的来源证明。

---

## 9. 相对 v1 的 delta

**delta:** 去掉 monolithic `canon_req` 与 `canon_resp_head` → 改为分字段(路由明文可还原 + 请求体/响应体各自哈希);删 headers 出自证。

**残余风险(接受):** headers **与 path 的 query string** 不绑定 → 恶意 relay 理论上能改**请求侧的 feature 开关**(如 `feature-flag` 头 / `?beta=` 查询)微调上游行为;但**改不了 model / endpoint 资源(path 已签)/ prompt / 响应**(model 在已签的 body 里、host+path 已签、响应完整性绑定),用户拿到的仍是官方模型对自己 prompt 的、未篡改的真响应。判定为可接受。

---

## 10. 决策点(已定)

- 规范化字节布局:**已定 = 文本**(本文 §4;可审计,未取每字段长度前缀二进制)。

---

## 11. 与早先评审的关系(已解决项)

早先 review(针对「v2 = canon_req + 可还原 servername」草案)的核心两条,**已被字段分解解决**,故本版不再适用:
- **① servername 与 canon_req.host 冗余** → **解决**:已无 monolithic canon_req,host 就是单一可还原字段 `upstream_host`,不存在重复。
- **② 建议先 preimage、v2 缓做** → **取代**:preimage 是给"monolithic 哈希"打的补丁;字段分解后**原生**就把 host/prompt 暴露成可独立验证的字段,且**彻底甩掉 header 规范化的脆性**,这是 preimage 给不了的结构性收益。preimage 不再需要。

仍然有效、已并入上文的告诫:规范化只剩声明布局(§4,对齐面已大缩)、`http_status` 偏 future-proof、model 走 UI 派生(best-effort)。
