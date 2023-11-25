# **Drson**[^1]

It downloads *JSON*[^2] data periodicaly from a website specified within the configuration file.
The data is then filtered and formated according to configured structure and then put to the Modbus registers which are then accessible via Modbus TCP or RTU.

[^1]: Princ Drsoň
[^2]: Princ Jasoň

Primarily created for extracting data from http://api.openweathermap.org but it's not limited to.

### The configuration file looks like
```
{
    "url":http://api.openweathermap.org/data/2.5/forecast?lat={lat}&lon={lon}&appid={appid}&units=metric",
    "period":3600,
    "dt":[32,0],
    "main":
    {
        "temp":[8,8],
        "feels_like":[8,8],
        "temp_min":[8,8],
```

Obviously you need to fill in your particular data at **{lat}** **{lon}** and **{appid}**, or plug in completely different site containing JSON data.
The *"period"* key designes number of seconds between consecutive reads.
Anything further is data to be parsed, then it's "name":[AR,RAY], where AR is number of bits of the output register/pair, RAY is fractional part if appropriate.
If fractional part is 0, then the data will be parsed as signed integer up to decimal dot. If fractional part is non-zero, the number will be parsed as double and then converted to
signed fixed point number of the specified precission.
Any other keys in *config.json* file and also in the web fetched file will be ignored.

```
Usage:
  ./drson [tcp|tcppi|rtu] - Modbus server for JSON web-api data retrieval
```
When run, then it behaves as modbus server over particular media, defaulting to TCP.
The binding addresses and ports are hardcoded only yet.
```
     if (use_backend == TCP) {
          ctx = modbus_new_tcp("127.0.0.1", 1502);
          query = malloc(MODBUS_TCP_MAX_ADU_LENGTH);
      } else if (use_backend == TCP_PI) {
          ctx = modbus_new_tcp_pi("::0", "1502");
          query = malloc(MODBUS_TCP_MAX_ADU_LENGTH);
      } else {
          ctx = modbus_new_rtu("/dev/ttyUSB0", 115200, 'N', 8, 1);
```

Drson is written in C, for JSON parsing awesome https://github.com/zserge/jsmn is utilized, web is acquired by https://curl.se/ and the Modbus server is built around https://libmodbus.org/. Thank you guys!

That's all for now.