# GitHub to ThreadFix Scan Upload
A tool to import security findings (i.e. CodeQL) to an application in ThreadFix.


# Example Workflow

Before you proceed further, make sure to have 3 key elements at hand as you'll need to add them as your [workflow secrets](https://github.com/Azure/actions-workflow-samples/blob/master/assets/create-secrets-for-GitHub-workflows.md). You'll need:

- Threadfix API Key
- Threadfix Instance URL
- Threadfix APP ID 

If you do not know the ID of your application, you can make a GET request to the [following endpoint](https://denimgroup.atlassian.net/wiki/spaces/TDOC/pages/2879324234/Get+Application+by+Name+or+Unique+ID+-+API):

`/rest/{version}/applications/{teamName}/lookup?name={appName}`


To use this workflow, simply include it in your action. Here's an example:

```yaml

on: [push]

jobs:
  Threadfix-action:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - name: Run Threadfix Connector
        uses: # Name of the action
        with: 
          TFIX_API_KEY: ${{secrets.TFIX_API_KEY}}
          TFIX_INSTANCE_URL: ${{secrets.TFIX_INSTANCE_URL}}
          TFIX_APP_ID: ${{secrets.TFIX_APP_ID}}

```

Here's an example on how to combine the Threadfix action with the CodeQl action, so that you can run them together.


```yaml
name: "Code Scanning and Threadfix Action "

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    #        ┌───────────── minute (0 - 59)
    #        │  ┌───────────── hour (0 - 23)
    #        │  │ ┌───────────── day of the month (1 - 31)
    #        │  │ │ ┌───────────── month (1 - 12 or JAN-DEC)
    #        │  │ │ │ ┌───────────── day of the week (0 - 6 or SUN-SAT)
    #        │  │ │ │ │
    #        │  │ │ │ │
    #        │  │ │ │ │
    #        *  * * * *
    - cron: '30 1 * * 0'

jobs:
  CodeQL-Build:
    # CodeQL runs on ubuntu-latest, windows-latest, and macos-latest
    runs-on: ubuntu-latest

    permissions:
      # required for all workflows
      security-events: write

      # only required for workflows in private repositories
      actions: read
      contents: read

    steps:
      - name: Checkout repository
        uses: actions/checkout@v3

      # Initializes the CodeQL tools for scanning.
      - name: Initialize CodeQL
        uses: github/codeql-action/init@v2
        # Override language selection by uncommenting this and choosing your languages
        # with:
        #   languages: go, javascript, csharp, python, cpp, java, ruby

      # Autobuild attempts to build any compiled languages (C/C++, C#, Go, or Java).
      # If this step fails, then you should remove it and run the build manually (see below).
      - name: Autobuild
        uses: github/codeql-action/autobuild@v2

      # ℹ️ Command-line programs to run using the OS shell.
      # 📚 See https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idstepsrun

      # ✏️ If the Autobuild fails above, remove it and uncomment the following
      #    three lines and modify them (or add more) to build your code if your
      #    project uses a compiled language

      #- run: |
      #     make bootstrap
      #     make release

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v2

Threadfix-action:
    runs-on: ubuntu-latest
    needs: CodeQL-Build
    steps:
      - name: Checkout repository
        uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - name: Run Threadfix Connector
        uses: # Name of the action
        with: 
          TFIX_API_KEY: ${{secrets.TFIX_API_KEY}}
          TFIX_INSTANCE_URL: ${{secrets.TFIX_INSTANCE_URL}}
          TFIX_APP_ID: ${{secrets.TFIX_APP_ID}}  

```

