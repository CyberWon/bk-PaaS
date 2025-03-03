### Functional description

create a new commit for a configuration

### Request Parameters

{{ common_args_desc }}

#### Interface Parameters

| Field       | Type      | Required  | Description |
|-------------|-----------|-----------|-------------|
| biz_id      |  string   | Yes     | business id (max_length: 64)    |
| app_id         |  string   | Yes     | application id     |
| cfg_id      |  string   | Yes     | config id    |
| memo        |  string   | No     | memo (max_length: 256) |

### Request Parameters Example

```json
{
    "bk_app_code": "xxx",
    "bk_app_secret": "xxx",
    "bk_token": "xxx",
    "biz_id": "xxx",
    "app_id": "A-0b67a798-e9c1-11e9-8c23-525400f99278",
    "cfg_id": "F-626889ba-e9c1-11e9-8c23-525400f99278",
    "memo": "my first commit"
}
```

### Return Result Example

```json
{
    "result": true,
    "code": 0,
    "message": "OK",
    "data": {
        "commit_id": "cd34e60a-ec95-11e9-b110-525400f99278"
    }
}
```

### Return Result Parameters Description

#### data

| Field   | Type   | Description |
|---------|--------|-------------|
| commit_id  | string | this configuration's new commit id |
