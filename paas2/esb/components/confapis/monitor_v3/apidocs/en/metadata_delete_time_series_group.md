

### Function description

Delete a custom timing group
Given a custom time series group ID, delete it

### Request parameters

{{ common_args_desc }}

#### Interface parameters

| Field | Type | Required | Description |
| -------------- | ------ | ---- | ----------- |
| time_series_group_id | int | yes | custom time series group ID |
| operator | string | Yes | operator |

#### Request example

```json
{
    "bk_app_code": "xxx",
    "bk_app_secret": "xxxxx",
    "bk_token": "xxxx",
    "time_series_group_id": 123,
    "operator": "admin"
}
```

### Return result

| Field | Type | Description |
| ---------- | ------ | ------------ |
| result | bool | Whether the request was successful |
| code | int | Returned status code |
| message | string | Description |
| data | dict | data |
| request_id | string | Request ID |

#### Example results

```json
{
    "message":"OK",
    "code":200,
    "data": { },
    "result":true,
    "request_id":"408233306947415bb1772a86b9536867"
}
```
