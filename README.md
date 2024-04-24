# ACSAlt
Native implemetation of Azure Code Signing client
- No external dependencies - no need to install Azure CLI, Python or .NET
- Way faster and more reliable than the original Microsoft implementation, especially under heavy load when signing multiple files at the same time

## Usage
Create metadata.json file. Note that it contains sensitive data, so make sure it's deleted when you no longer need it
```
{
    "tenant": "acs tenant",
    "client_id": "acs user",
    "secret": "acs pass",
    "endpoint": "https://wus2.codesigning.azure.net/",
    "account": "ACS account name",
    "profile": "ACS signing profile name,
    "correlation_id": "correlation guid"
}
```
Run 
```
signtool.exe sign /tr <timestamping url> /td sha256 /fd sha256 /v /dlib acsalt.dll /dmdf metadata.json target.exe
```

## Known issues
- OAuth re-authentication flow is not perfect - the code performs full authentication instead of updating the ticket. But it works and I'm too lazy to fix it.
- Developed a while ago, not updated specifically for the release of Trusted Signing, but probably still works
