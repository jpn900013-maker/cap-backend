# 9Captcha Solver API

A simple HTTP API for solving hCaptcha challenges using the 9Captcha service.

## Setup

1. Install the required dependencies:
```bash
pip install -r requirements.txt
```

2. Run the API server:
```bash
python server.py
```

By default, the server will run on `http://0.0.0.0:5000`.

## API Endpoints

### 1. Create Task

**Endpoint**: `/create_task`
**Method**: `POST`
**Description**: Creates a new captcha solving task.

**Request Body**:
```json
{
  "key": "your_9captcha_api_key",
  "type": "hcaptcha_basic",
  "data": {
    "sitekey": "hcaptcha_site_key",
    "siteurl": "discord.com",
    "proxy": "username:password@host:port",
    "rqdata": "optional_rqdata"
  }
}
```

**Response**:
```json
{
  "status": "success",
  "task_id": "task_identifier"
}
```

### 2. Get Result

**Endpoint**: `/get_result/{task_id}`
**Method**: `GET`
**Request Body**:
```json
{
  "key": "your_9captcha_api_key"
}
```

**Response**:
```json
{
  "status": "success",
  "solution": "captcha_solution_token"
}
```

Or, if still solving:
```json
{
  "status": "solving"
}
```

## Additional API Endpoints

### 3. Get Balance

**Endpoint**: `/get_balance`
**Method**: `POST`
**Description**: Get current balance for your account.

**Request Body**:
```json
{
  "key": "your_9captcha_api_key"
}
```

**Response**:
```json
{
  "status": "success",
  "balance": 10.5
}
```

### 4. Get Daily Usage

**Endpoint**: `/get_daily_usage`
**Method**: `POST`
**Description**: Get number of requests in the last 24 hours.

**Request Body**:
```json
{
  "key": "your_9captcha_api_key"
}
```

**Response**:
```json
{
  "status": "success",
  "daily_requests": 150
}
```

### 5. Get Success Rate

**Endpoint**: `/get_success_rate`
**Method**: `POST`
**Description**: Get your success rate for solved captchas.

**Request Body**:
```json
{
  "key": "your_9captcha_api_key"
}
```

**Response**:
```json
{
  "status": "success",
  "success_rate": 95.5
}
```

## Example Usage with Python

Please check `examples/example_client.py` for a demo of how to query the endpoints.

## Notes

- You need a valid 9Captcha API key to use this service
- Always provide a proxy in the correct format (username:password@host:port)
- Pricing is based on your account tier (basic or enterprise)
