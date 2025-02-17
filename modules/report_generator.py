import json
import csv
import os

class ReportGenerator:
    @staticmethod
    def generate(findings, platform, output_format="json"):
        """
        Generates a security scan report in JSON, HTML, or CSV format.
        """
        # Ensure reports directory exists
        report_dir = "reports"
        os.makedirs(report_dir, exist_ok=True)

        # Determine filename based on format
        filename = os.path.join(report_dir, f"{platform}_scan_report.{output_format}")

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
        """
        Generates a JSON report.
        """
        with open(filename, "w") as f:
            json.dump(findings, f, indent=4)
        return filename

    @staticmethod
    def generate_html(findings, filename):
        """
        Generates an HTML report with a table view.
        """
        html_content = """
        <html>
        <head>
            <title>Cloud Security Scan Report</title>
            <style>
                body { font-family: Arial, sans-serif; }
                table { width: 100%%; border-collapse: collapse; margin-top: 20px; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f4f4f4; }
            </style>
        </head>
        <body>
            <h1>Cloud Security Scan Report</h1>
            <table>
                <tr>
                    <th>Type</th>
                    <th>Resource</th>
                    <th>Issue</th>
                </tr>
        """

        if findings:
            for finding in findings:
                html_content += f"""
                <tr>
                    <td>{finding.get("Type", "Unknown")}</td>
                    <td>{finding.get("Resource", "N/A")}</td>
                    <td>{finding.get("Issue", "No details available")}</td>
                </tr>
                """
        else:
            html_content += """
                <tr>
                    <td colspan="3">✅ No security misconfigurations detected.</td>
                </tr>
            """

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
        """
        Generates a CSV report.
        """
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Type", "Resource", "Issue"])

            if findings:
                for finding in findings:
                    writer.writerow([
                        finding.get("Type", "Unknown"),
                        finding.get("Resource", "N/A"),
                        finding.get("Issue", "No details available")
                    ])
            else:
                writer.writerow(["No security misconfigurations detected.", "", ""])

        return filename
