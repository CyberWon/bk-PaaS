### 功能描述

查询指定版本或策略匹配的应用实例列表

### 请求参数

{{ common_args_desc }}

#### 接口参数

| 字段             |  类型     | 必选   |  描述    |
|------------------|-----------|--------|----------|
| biz_id           |  string   | 是     | 业务ID   |
| app_id           |  string   | 是     | 应用ID   |
| strategy_id      |  string   | 否     | 策略ID   |
| release_id       |  string   | 否     | 版本ID   |
| multi_release_id |  string   | 否     | 混合版本ID  |
| page             |  object   | 是     | 分页设置 |

#### page

| 字段         |  类型  | 必选   |  描述      |
|--------------|--------|--------|------------|
| return_total |  bool  | 否     | 是否返回总记录条数, 默认不返回 |
| start        |  int   | 是     | 记录开始位置 |
| limit        |  int   | 是     | 每页限制条数,最大500 |

### 请求参数示例

```json
{
    "bk_app_code": "xxx",
    "bk_app_secret": "xxx",
    "bk_token": "xxx",
    "biz_id": "xxx",
    "app_id": "A-0b67a798-e9c1-11e9-8c23-525400f99278",
    "strategy_id": "S-0b67a798-e9c1-11e9-8c23-525400f99278",
    "page": {
        "start": 0,
        "limit": 500
    }
}
```

或

```json
{
    "bk_app_code": "xxx",
    "bk_app_secret": "xxx",
    "bk_token": "xxx",
    "biz_id": "xxx",
    "app_id": "A-0b67a798-e9c1-11e9-8c23-525400f99278",
    "release_id": "R-0b67a798-e9c1-11e9-8c23-525400f99278",
    "page": {
        "start": 0,
        "limit": 500
    }
}
```

或

```json
{
    "bk_app_code": "xxx",
    "bk_app_secret": "xxx",
    "bk_token": "xxx",
    "biz_id": "xxx",
    "app_id": "A-0b67a798-e9c1-11e9-8c23-525400f99278",
    "multi_release_id": "MR-0b67a798-e9c1-11e9-8c23-525400f99278",
    "page": {
        "start": 0,
        "limit": 500
    }
}
```

### 返回结果示例

```json
{
    "result": true,
    "code": 0,
    "message": "OK",
    "data": {
        "total_count": 1,
        "info": [
            {
                "biz_id": "XXX",
                "app_id": "A-0b67a798-e9c1-11e9-8c23-525400f99278",
                "cloud_id": "0",
                "ip": "127.0.0.1",
                "path": "/data/configs",
                "labels":"{\"Labels\":{\"version\":\"1.0\"}}",
                "state": 0,
                "created_at": "2019-07-29 11:57:20",
                "updated_at": "2019-07-29 11:57:20"
            }
        ]
    }
}
```

### 返回结果参数

#### data

| 字段        | 类型      | 描述      |
|-------------|-----------|-----------|
| total_count | int       | 当前规则能匹配到的总记录条数 |
| info        | array     | 查询返回的数据 |

#### data.info[n]

| 字段           | 类型      | 描述    |
|----------------|-----------|---------|
| biz_id         |  string   | 业务ID  |
| app_id         |  string   | 应用ID  |
| cloud_id       |  string   | 云区域/网络ID |
| ip             |  string   | 实例IP |
| path           |  string   | 实例配置缓存路径 |
| labels         |  string   | 实例标签集合JSON字符串 |
| state          |  integer  | 状态 默认0: 正常 |
| created_at     |  string   | 创建时间 |
| updated_at     |  string   | 更新时间 |
