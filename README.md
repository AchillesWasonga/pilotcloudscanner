# pilotcloudscanner
How to run this tool
Install aws-cli
Install az-cli
Activate a python virtual environment
For AWS run python main.py --platform aws --output json
For Azure run python main.py --platform azure --output json
Where --platform is the platform you are using and 
--output json tells it to output the findings in json format
After that cat into reports/json to view findings

