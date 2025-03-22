import json
import csv
import os
import html
import logging

class ReportGenerator:
    @staticmethod
    def generate(findings, platform, output_format="json"):
        """
        Generates a cloud security scan report in the specified format.
        Supported formats: JSON, HTML, CSV.
        """
        report_dir = "reports"
        os.makedirs(report_dir, exist_ok=True)

        filename = os.path.join(report_dir, f"{platform}_scan_report.{output_format}")

        logging.info(f"Generating {output_format.upper()} report for platform: {platform}")

        if output_format == "json":
            return ReportGenerator.generate_json(findings, filename)
        elif output_format == "html":
            return ReportGenerator.generate_html(findings, filename)
        elif output_format == "csv":
            return ReportGenerator.generate_csv(findings, filename)
        else:
            raise ValueError("Unsupported output format. Use 'json', 'html', or 'csv'.")

    @staticmethod
    def generate_json(findings, filename):
        """Generates a JSON report."""
        with open(filename, "w") as f:
            json.dump(findings, f, indent=4)
        return filename

    @staticmethod
    def generate_html(findings, filename):
        """Generates an HTML report with a dynamic table based on finding fields."""
        html_content = """
        <html>
        <head>
            <title>Cloud Security Scan Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
                th { background-color: #f4f4f4; }
            </style>
        </head>
        <body>
            <h1>Cloud Security Scan Report</h1>
            <table>
        """

        if findings:
            headers = sorted(set(k for d in findings for k in d.keys()))
            html_content += "<tr>" + "".join(f"<th>{html.escape(h)}</th>" for h in headers) + "</tr>"

            for finding in findings:
                html_content += "<tr>" + "".join(
                    f"<td>{html.escape(str(finding.get(h, 'N/A')))}</td>" for h in headers
                ) + "</tr>"
        else:
            html_content += "<tr><td colspan='3'>No security misconfigurations detected.</td></tr>"

        html_content += """
            </table>
        </body>
        </html>
        """

        with open(filename, "w") as f:
            f.write(html_content)
        return filename

    @staticmethod
    def generate_csv(findings, filename):
        """Generates a CSV report with dynamic headers based on findings."""
        if findings:
            headers = sorted(set(k for d in findings for k in d.keys()))
        else:
            headers = ["Message"]

        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(headers)

            if findings:
                for finding in findings:
                    row = [finding.get(h, "N/A") for h in headers]
                    writer.writerow(row)
            else:
                writer.writerow(["No security misconfigurations detected."])

        return filename
