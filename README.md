# Py-Interactsh
Dnslog Interactsh的Py版接口查询

## Demo

```
Interactsh = Interactsh()
domain = Interactsh.GetDomain()
requests.get("http://" + domain, timeout=3)
print(Interactsh.Poll())
```
