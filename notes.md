# Notes


- Rename Secrets before production version
- The URL should be broken down the following way:

```curl
curl --insecure -H 'Accept: application/json' -H "Authorization: APIKEY {secrets.tfix_API_key}" -X POST --form file=@path/to/file/www_example_url_com_webinspect_scan.xml ${{secrets.tfix_instance_URL}}/threadfix/rest/latest/applications/${{secrets.tfix_API_ID}}/upload
```
And (If we decide to use it)

```curl
curl --insecure -H 'Accept: application/json' -H "Authorization: APIKEY ${{secrets.tfix_API_key}}" ${{tfix_instance_URL}}/rest/latest/applications/${{secrets.tfix_API_ID}}
```

- The output file includes `description` and `summary`, which include the same value. Need to look into this.

```json

 {
      "nativeId": "QJRJGjviyaooZHsSkemTQRLvCDEPJDBRcQjFhLwpSjLATTorlTMfTWGSTtbOHLOqoARfHRNPtCguvolOabafccMtpKqkzzYvZykdOeIbagBYjyhTWwZlXGcOUHikNNdyepUrNRxXoGUriGnyXEkeTmYNKUmWknfxojoeiYYtiTBTANjYDXvMDuRPYUbunghgTkMPaSWetBtOjZEkiSgxMykvRHmvRXVdhrTsDyXuzyhSgNFMCuLNYgWZwCdDLgcl",
      "severity": "Critical",
      "nativeSeverity": "warning",
      "mappings": [{ "mappingType": "CWE", "value": "502", "primary": true }],
      "summary": "Deserialization of user-controlled data",
      "description": "Deserialization of user-controlled data",
      "staticDetails": {
        "dataFlow": [
          {
            "file": "https://api.github.com/repos/dsp-testing/Alex-testing/code-scanning/alerts/1/instances",
            "lineNumber": 6,
            "columnNumber": 24,
            "text": ""
          }
        ],
        "parameter": "",
        "file": "https://api.github.com/repos/dsp-testing/Alex-testing/code-scanning/alerts/1/instances"
      }
    }

```
