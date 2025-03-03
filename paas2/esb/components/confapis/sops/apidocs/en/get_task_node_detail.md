### Functional description

Query a task node execution details

#### Interface Parameters

|   Field         |  Type       | Required |  Description     |
|---------------|------------|--------|------------------|
|   bk_biz_id   |   string   |   YES   |  the business ID             |
|   task_id     |   string   |   YES   |  the task ID   |
|   node_id        | string     | YES         | the node ID of task                        |
|   component_code| string     | NO         | the code of Standard Plugin, this field is required when query a Standard Plugin node |
|   subprocess_stack| string   | NO         | stack of SubProcess, format is json  |

### Request Parameters Example

```
{
    "bk_app_code": "esb_test",
    "bk_app_secret": "xxx",
    "bk_token": "xxx",
    "bk_username": "xxx",
    "bk_biz_id": "2",
    "task_id": "10",
    "node_id": "node0df0431f8f553925af01a94854bd"
    "subprocess_stack": "[\"nodeaaa0ce51d2143aa9b0dbc27cb7df\"]",
    "component_code": "job_fast_execute_script",
}
```

### Return Result Example

```
{
    "message": "",
    "data": {
        "inputs": {
            "job_account": "root",
            "job_script_timeout": "",
            "job_script_source": "manual",
            "job_script_list_public": "",
            "job_content": "echo 0\nexit 0",
            "job_script_type": "1",
            "job_script_param": "",
            "job_script_list_general": "",
            "job_ip_list": "127.0.0.1"
        },
        "retry": 0,
        "name": "<class "pipeline.core.flow.activity.ServiceActivity">",
        "finish_time": "2019-01-17 22:02:46 +0800",
        "skip": false,
        "start_time": "2019-01-17 22:02:37 +0800",
        "children": {},
        "histories": [],
        "ex_data": null,
        "elapsed_time": 9,
        "outputs": [
            {
                "value": 407584,
                "name": "JOB任务ID",
                "key": "job_inst_id",
                "preset": true
            },
            {
                "value": "",
                "name": "JOB任务链接",
                "key": "job_inst_url",
                "preset": true
            },
            {
                "value": true,
                "name": "执行结果",
                "key": "_result",
                "preset": true
            }
        ],
        "state": "FINISHED",
        "version": "23ac8c29f62b3337aafcf1f538d277f8",
        "error_ignorable": false,
        "id": "node0df0431f8f553925af01a94854bd",
        "loop": 1
    },
    "result": true,
    "request_id": "xxx",
    "trace_id": "xxx"
}
```

### Return Result Description

| Field      | Type      | Description      |
|-----------|----------|-----------|
|  result   |    bool    |      true or false, indicate success or failure                      |
|  data     |    dict    |      data returned when result is true, details are described below  |
|  message  |    string  |      error message returned when result is false                     |
|  request_id     |    string  | esb request id         |
|  trace_id     |    string  | open telemetry trace_id       |

#### data

| Field      | Type      | Description      |
|-----------|----------|-----------|
|  id           | string     | the unique ID of node       |
|  start_time   | string     | start time of last execution    |
|  finish_time  | string     | finish time of last execution   |
|  elapsed_time | int        | elapsed time of last execution  |
|  state        | string     | execution status，CREATED,RUNNING,FAILED,NODE_SUSPENDED,FINISHED |
|  skip         | bool       | skipped manually                   |
|  retry        | int        | retry times                       |
|  inputs       | dict       | inputs parameters, format is key：value      |
|  outputs      | list       | outputs info of this node，details are described below    |
|  ex_data      | string     | failure detail of this node，format is json or HTML、string |
|  histories    | list       | retry records, details are described below   |

#### data.outputs[]
| Field      | Type      | Description      |
| ------------  | ---------- | ------------------------------ |
|  name         | string     | name of output variable                   |
|  value        | string、int、bool、dict、list | value  |
|  key          | string     | KEY                   |
|  preset       | bool       | where to display in Standard Plugins   |


#### data.histories[]
|      Field     |     Type   |               Description             |
| ------------  | ---------- | ------------------------------ |
|  start_time   | string     | start time    |
|  finish_time  | string     | finish time    |
|  elapsed_time | int        | elapsed time   |
|  state        | string     | execution status，CREATED,RUNNING,FAILED,NODE_SUSPENDED,FINISHED |
|  skip         | bool       | skipped manually                   |
|  retry        | int        | retry times                       |
|  inputs       | dict       | inputs parameters, format is key：value      |
|  outputs      | list       | outputs info of this node，details are described below    |
|  ex_data      | string     | failure detail of this node，format is json or HTML、string |
|  histories    | list       | retry records, details are described below   |
