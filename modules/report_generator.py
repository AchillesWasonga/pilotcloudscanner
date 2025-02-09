import json

class ReportGenerator:
    @staticmethod
    def generate(findings, platform):
        filename = f"{platform}_scan_report.json"
        with open(filename, "w") as f:
            json.dump(findings, f, indent=4)
        return filename
